# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'QES signing values', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
  end

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:submission) { submitter.submission }
  let(:text_field) { submission.template_fields.find { |field| field['type'] == 'text' } }
  let(:qes_field) { submission.template_fields.find { |field| field['type'] == 'qes' } }
  let(:pkcs) { QesHelpers.pkcs12 }

  def start_session(headers = {})
    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: qes_field['uuid'] }, headers:
  end

  def prepare_signature(token)
    post "/qes/sessions/#{token}/certificate", params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }
  end

  def complete_signature(token, session)
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.reload.signed_attrs_der)
    post "/qes/sessions/#{token}/complete", params: { signature: Base64.strict_encode64(signature) }
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
  end

  it 'returns 422 values_changed when signed values changed before session creation' do
    create(:qes_session, :with_values_snapshot, submitter:, state: 'completed', level: 'ades')
    submitter.update_columns(values: submitter.values.merge(text_field['uuid'] => 'Changed after signing'))

    expect { start_session }.not_to change(QesSession, :count)

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('values_changed')
  end

  it 'returns 422 values_changed when signed values changed before data_to_sign' do
    start_session
    expect(response).to have_http_status(:created)
    token = response.parsed_body.fetch('token')
    session = QesSession.find(response.parsed_body.fetch('id'))
    create(:qes_session, :with_values_snapshot, submitter:, state: 'completed', level: 'ades')
    submitter.update_columns(values: submitter.values.merge(text_field['uuid'] => 'Changed after signing'))
    expect(Qes::TbsDocument).not_to receive(:build)

    prepare_signature(token)

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('values_changed')
    expect(session.reload.state).to eq('awaiting_app')
    expect(session.tbs_document).not_to be_attached
  end

  %i[form api].each do |path|
    it "requires the text placed after QES and freezes it after signing (#{path})" do
      submission.update!(template_fields: [qes_field, text_field])
      submitter.update!(values: {})
      headers = path == :api ? { 'X-Auth-Token' => submission.template.author.access_token.token } : {}

      expect { start_session(headers) }.not_to change(QesSession, :count)
      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body).to include('error' => 'fields_incomplete',
                                             'missing_fields' => [text_field['name']])

      if path == :api
        put "/api/submitters/#{submitter.id}", params: { values: { text_field['uuid'] => 'Agreed text' } },
                                             headers:, as: :json
      else
        put "/s/#{submitter.slug}", params: { values: { text_field['uuid'] => 'Agreed text' } }
      end
      expect(response).to have_http_status(:ok)

      start_session(headers)
      expect(response).to have_http_status(:created)
      token = response.parsed_body['token']
      session = QesSession.find(response.parsed_body['id'])

      prepare_signature(token)
      expect(response).to have_http_status(:ok)
      expect(session.reload.tbs_document.blob.metadata['qes_values']).to eq(text_field['uuid'] => 'Agreed text')
      complete_signature(token, session)

      put "/s/#{submitter.slug}", params: { values: { text_field['uuid'] => 'Changed text' } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('Signed field values cannot be changed')
      expect(submitter.reload.values[text_field['uuid']]).to eq('Agreed text')

      if path == :api
        put "/api/submitters/#{submitter.id}", params: { completed: true }, headers:, as: :json
      else
        put "/s/#{submitter.slug}", params: { completed: 'true', values: { qes_field['uuid'] => session.value_token } }
      end
      expect(response).to have_http_status(:ok)
      expect(submitter.reload.completed_at).to be_present

      put "/api/submitters/#{submitter.id}", params: { values: { text_field['uuid'] => 'Changed after completion' } },
                                           headers: { 'X-Auth-Token' => submission.template.author.access_token.token },
                                           as: :json
      expect(response).to have_http_status(:unprocessable_content)
      expect(submitter.reload.values[text_field['uuid']]).to eq('Agreed text')
    end
  end

  it 'returns the frozen non-QES values to the browser after certificate signing' do
    submitter.update!(values: { text_field['uuid'] => 'Frozen text' })
    start_session
    expect(response).to have_http_status(:created)
    token = response.parsed_body.fetch('token')

    prepare_signature(token)
    expect(response).to have_http_status(:ok)

    get "/qes/sessions/#{token}"

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['values']).to eq(text_field['uuid'] => 'Frozen text')
  end

  it 'rechecks required values when the certificate arrives' do
    start_session
    expect(response).to have_http_status(:created)
    token = response.parsed_body['token']
    session = QesSession.find(response.parsed_body['id'])
    submitter.update!(values: {})
    expect(Qes::TbsDocument).not_to receive(:build)

    prepare_signature(token)

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body).to include('error' => 'fields_incomplete',
                                           'missing_fields' => [text_field['name']])
    expect(session.reload.state).to eq('awaiting_app')
    expect(session.tbs_document).not_to be_attached
  end

  %i[form api].each do |path|
    it "renders stamp, date defaults and formula values before signing and preserves them at completion (#{path})" do
      date = text_field.deep_dup.merge('uuid' => SecureRandom.uuid, 'name' => 'Prepared date',
                                      'readonly' => true, 'type' => 'date', 'default_value' => '{{date}}',
                                      'preferences' => { 'format' => 'YYYY-MM-DD' })
      formula = text_field.deep_dup.merge('uuid' => SecureRandom.uuid, 'name' => 'Calculated value',
                                         'type' => 'number', 'readonly' => true,
                                         'preferences' => { 'formula' => '1 + 2' })
      stamp = text_field.deep_dup.merge('uuid' => SecureRandom.uuid, 'name' => 'Company stamp',
                                       'type' => 'stamp', 'preferences' => { 'with_logo' => false })
      stamp['areas'].first['y'] = 0.4
      date['areas'].first['y'] = 0.2
      formula['areas'].first['y'] = 0.3
      submission.update!(template_fields: [qes_field, text_field, date, formula, stamp])
      expect(submission.template_fields.pluck('type')).not_to include('verification')
      expected_date = TimeUtils.current_date_value(nil, submitter.account.timezone)

      start_session
      expect(response).to have_http_status(:created)
      token = response.parsed_body['token']
      session = QesSession.find(response.parsed_body['id'])
      expect(submitter.reload.values).not_to have_key(date['uuid'])
      expect(submitter.values).not_to have_key(formula['uuid'])
      original_values = submitter.values.deep_dup

      expect(Qes::TbsDocument).to receive(:build).and_wrap_original do |original, signer, *args, **options|
        expect(signer.values[date['uuid']]).to eq(expected_date)
        expect(signer.attachments.find { |attachment| attachment.uuid == signer.values[stamp['uuid']] }).to be_present
        # OSS výpočet číselného vzorce vrací 0; ověřujeme skutečnou pipeline.
        expect(signer.values[formula['uuid']]).to eq(0)
        expect(Submitter.find(signer.id).values).to eq(original_values)
        original.call(signer, *args, **options)
      end

      prepare_signature(token)
      expect(response).to have_http_status(:ok)
      snapshot = session.reload.tbs_document.blob.metadata['qes_values']
      expect(snapshot).to include(date['uuid'] => expected_date, formula['uuid'] => 0)
      expect(snapshot[stamp['uuid']]).to be_present
      expect(submitter.reload.values).to eq(snapshot)
      expect(submitter.attachments.find_by(uuid: snapshot[stamp['uuid']])).to be_present
      text = Pdfium::Document.open_io(StringIO.new(session.tbs_document.download)) do |pdf|
        (0...pdf.page_count).map { |index| pdf.get_page(index).text }.join("\n")
      end
      expect(text).to include(expected_date)
      complete_signature(token, session)

      travel_to(1.day.from_now) do
        expect(Submitters::CreateStampAttachment).not_to receive(:build_attachment)
        expect(Submitters::SubmitValues).not_to receive(:merge_default_values)
        expect(Submitters::SubmitValues).not_to receive(:build_formula_values)

        if path == :api
          headers = { 'X-Auth-Token' => submission.template.author.access_token.token }
          put "/api/submitters/#{submitter.id}", params: { completed: true },
                                               headers:, as: :json
        else
          put "/s/#{submitter.slug}", params: { completed: 'true',
                                               values: { qes_field['uuid'] => session.value_token } }
        end
        expect(response).to have_http_status(:ok)
        expect(submitter.reload.completed_at).to be_present
        expect(Qes::ValueValidator.non_qes_values(submitter.values, submitter)).to eq(snapshot)
      end
    end
  end
end
