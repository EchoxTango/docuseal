# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Qes sessions API', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
  end

  let(:pkcs) { QesHelpers.pkcs12 }

  def create_qes_session(state: 'awaiting_app', token: nil, expires_at: 10.minutes.from_now, level: 'ades')
    submitter = QesHelpers.build_qes_submitter(level:)
    field = submitter.submission.template_fields.find { |f| f['type'] == 'qes' }

    session = create(:qes_session, submitter:, submission: submitter.submission,
                                    account: submitter.account, field_uuid: field['uuid'],
                                    state: 'created', expires_at:)

    Qes::SessionManager.transition!(session, 'prepared')

    if token
      session.update!(token_digest: Qes::Token.digest(token))
    end

    Qes::SessionManager.transition!(session, 'awaiting_app') if state != 'created'
    session.update!(state:) if state == 'created'
    session.update!(state:) if state == 'failed'

    [session, submitter]
  end


  it 'creates a session for a submission with blank template_fields' do
    submitter = QesHelpers.build_qes_submitter
    submitter.submission.update!(template_fields: nil, template_schema: nil)
    field = submitter.submission.template.fields.find { |f| f['type'] == 'qes' }

    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: field['uuid'] }

    expect(response).to have_http_status(:created)
    expect(response.parsed_body['state']).to eq('awaiting_app')
    expect(response.parsed_body['qr_svg']).to include('<svg')
  end

  it 'returns 404 for an unknown token' do
    get '/qes/sessions/unknown'

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body['error']).to eq('unknown_token')
  end

  it 'keeps an awaiting signature session and returns its polling id without a new token' do
    session, submitter = create_qes_session(token: 'in-progress')
    session.update!(state: 'awaiting_signature')
    digest = session.token_digest

    expect do
      post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: session.field_uuid }
    end.not_to change(QesSession, :count)

    expect(response).to have_http_status(:conflict)
    expect(response.parsed_body).to include('error' => 'signature_in_progress', 'id' => session.id,
                                            'session_id' => session.id, 'state' => 'awaiting_signature')
    expect(response.parsed_body).not_to have_key('token')
    expect(session.reload.state).to eq('awaiting_signature')
    expect(session.token_digest).to eq(digest)
  end

  %w[awaiting_app app_opened].each do |state|
    it "replaces an abandoned #{state} session" do
      session, submitter = create_qes_session(token: 'replace')
      session.update!(state:)

      post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: session.field_uuid }

      expect(response).to have_http_status(:created)
      expect(response.parsed_body['id']).not_to eq(session.id)
      expect(session.reload.state).to eq('cancelled')
    end
  end

  it 'cancels the awaiting signature returned after reload and creates a fresh session' do
    session, submitter = create_qes_session(token: 'cancel-and-restart')
    session.update!(state: 'awaiting_signature')
    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: session.field_uuid }
    expect(response).to have_http_status(:conflict)
    session_id = response.parsed_body.fetch('id')

    post "/s/#{submitter.slug}/qes_sessions/#{session_id}/cancel"
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('cancelled')
    expect(session.reload.state).to eq('cancelled')

    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: session.field_uuid }
    expect(response).to have_http_status(:created)
    expect(response.parsed_body['id']).not_to eq(session_id)
    expect(response.parsed_body['token']).to be_present
    expect(response.parsed_body['qr_svg']).to include('<svg')
    expect(response.parsed_body['state']).to eq('awaiting_app')

    get '/qes/sessions/cancel-and-restart'
    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('used_token')
  end

  it 'does not allow a submitter to cancel another submitter signature' do
    session, = create_qes_session(token: 'other-signature')
    session.update!(state: 'awaiting_signature')
    other = QesHelpers.build_qes_submitter

    post "/s/#{other.slug}/qes_sessions/#{session.id}/cancel"

    expect(response).to have_http_status(:not_found)
    expect(session.reload.state).to eq('awaiting_signature')
  end

  it 'does not cancel a signature that completed while the form was open' do
    session, submitter = create_qes_session(token: 'already-completed')
    session.update!(state: 'completed')

    post "/s/#{submitter.slug}/qes_sessions/#{session.id}/cancel"

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
    expect(session.reload.state).to eq('completed')
  end

  it 'does not cancel an awaiting signature for another field' do
    submission = QesHelpers.build_qes_submission(qes_fields_per_submitter: 2)
    submitter = submission.submitters.first
    first_field, second_field = Qes.template_fields(submission).select { |field| field['type'] == 'qes' }
    session = create(:qes_session, submitter:, field_uuid: first_field['uuid'], state: 'awaiting_signature')

    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: second_field['uuid'] }

    expect(response).to have_http_status(:created)
    expect(session.reload.state).to eq('awaiting_signature')
  end

  it 'allows retrying completion after seal_failed and exposes both finishing states' do
    session, _submitter = create_qes_session(token: 'retry-seal')
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    post '/qes/sessions/retry-seal/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) }
    }
    expect(response).to have_http_status(:ok)
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.reload.signed_attrs_der)
    attempts = 0
    allow(Qes::Seal).to receive(:apply).and_wrap_original do |original, pdf, *args, **kwargs|
      attempts += 1
      attempts == 1 ? [pdf, 'failed'] : original.call(pdf, *args, **kwargs)
    end

    post '/qes/sessions/retry-seal/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('seal_failed')
    expect(session.reload.state).to eq('awaiting_signature')
    expect(session.failure_code).to eq('seal_failed')
    expect(session.failed_at).to be_nil
    expect(session.final_document).not_to be_attached

    post '/qes/sessions/retry-seal/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include('state' => 'completed', 'seal_state' => 'applied',
                                            'doc_timestamp_state' => 'none',
                                            'signing_time' => session.signing_time.utc.iso8601)
    expect(session.reload.failure_code).to be_nil
    get "/s/#{session.submitter.slug}/qes_sessions/#{session.id}", headers: { 'Accept' => 'application/json' }
    expect(response.parsed_body).to include('seal_state' => 'applied', 'doc_timestamp_state' => 'none')
  end

  it 'refuses a later signer when conditional documents differ from the signed manifest' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    submission = QesHelpers.build_qes_submission(count: 2, attachment_count: 2, field_types: [],
                                                qes_attachment_index: 1)
    first, second = submission.submitters.order(:id).to_a
    first_field, second_field = submission.template_fields.select { |field| field['type'] == 'qes' }
    conditional_uuid, included_uuid = submission.template_schema.pluck('attachment_uuid')
    condition = { 'uuid' => SecureRandom.uuid, 'name' => 'Include attachment', 'type' => 'text',
                  'required' => false, 'submitter_uuid' => second.uuid, 'areas' => [] }
    schema = submission.template_schema.deep_dup
    schema.first['conditions'] = [{ 'field_uuid' => condition['uuid'], 'action' => 'not_empty' }]
    submission.update!(template_schema: schema, template_fields: submission.template_fields + [condition])
    first_session = create(:qes_session, submitter: first, field_uuid: first_field['uuid'])
    provider = Qes::Providers::Mock.new(first_session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                                    password: 'test')
    provider.sign!(first, first_field)
    first.update!(completed_at: Time.current)
    manifest = first_session.reload.tbs_document.blob.metadata.fetch('qes_document_manifest')
    expect(manifest).to eq([{ 'attachment_uuid' => included_uuid, 'page_count' => 1 }])
    expect(HexaPDF::Document.new(io: StringIO.new(first_session.final_document.download)).pages.size).to eq(1)

    second.update!(values: { condition['uuid'] => 'Include' })
    expect(Submissions.filtered_conditions_schema(submission.reload).pluck('attachment_uuid'))
      .to eq([conditional_uuid, included_uuid])
    expect do
      post "/s/#{second.slug}/qes_sessions", params: { field_uuid: second_field['uuid'] }
    end.not_to change(QesSession, :count)
    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('document_set_changed')
    expect { Qes::TbsDocument.build(second.reload, second_field) }
      .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:document_set_changed) }

    # The persisted manifest supplies offsets again once the original set is restored.
    second.update!(values: {})
    second_session = create(:qes_session, submitter: second, field_uuid: second_field['uuid'], state: 'awaiting_app')
    Qes::Providers::MobileApp.new(second_session).data_to_sign(pkcs.certificate.to_der, chain: pkcs.ca_certs || [])
    expect(second_session.reload.tbs_document.blob.metadata['qes_document_manifest']).to eq(manifest)
    expect(Qes::TbsDocument.page_offsets(submission, manifest:)).to eq(included_uuid => 0)
    tbs = HexaPDF::Document.new(io: StringIO.new(second_session.tbs_document.download))
    expect(tbs.pages.size).to eq(1)
    expect(second_session.tbs_document.download).to start_with(first_session.final_document.download)
  end

  it 'reports unchecked revocation only when the signing certificate has no CRL DP' do
    Qes::Config[:require_ltv] = false
    key, certificate = QesHelpers.self_signed_qc_sscd_certificate
    no_dp_pkcs = OpenSSL::PKCS12.create('test', 'no-dp', key, certificate)
    allow(Qes).to receive(:trust_roots).and_return([certificate])
    expect(Qes::Ltv.crl_distribution_point?(certificate)).to be false
    expect(Qes::Ltv).not_to receive(:fetch_first_crl)
    session, = create_qes_session(token: 'no-crls')
    post '/qes/sessions/no-crls/certificate', params: {
      certificate: Base64.strict_encode64(no_dp_pkcs.certificate.to_der), key_location: 'card',
      chain: (no_dp_pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) }
    }
    expect(response).to have_http_status(:ok)
    signature = no_dp_pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.reload.signed_attrs_der)
    post '/qes/sessions/no-crls/complete', params: { signature: Base64.strict_encode64(signature) }
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include('state' => 'completed', 'revocation' => 'not_checked')
    expect(response.parsed_body.dig('validation', 'revocation')).to eq('not_checked')
    expect(session.reload.validation_report['revocation']).to eq('not_checked')
    get '/qes/sessions/no-crls'
    expect(response.parsed_body['revocation']).to eq('not_checked')
  end

  it 'returns a completed session after its link expiry' do
    session, _submitter = create_qes_session(token: 'completed-expired', expires_at: 1.minute.ago)
    session.update!(state: 'completed')

    get '/qes/sessions/completed-expired'

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
  end

  it 'returns the completed session instead of starting a new one' do
    session, submitter = create_qes_session(token: 'already-done')
    session.tbs_document.attach(
      io: StringIO.new('%PDF-snapshot'), filename: 'snapshot.pdf', content_type: 'application/pdf',
      metadata: { qes_values: Qes::ValueValidator.non_qes_values(submitter.values, submitter),
                  qes_document_manifest: Qes::TbsDocument.manifest_for(submitter.submission) }
    )
    session.reload

    session.update!(state: 'completed')

    expect do
      post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: session.field_uuid }
    end.not_to change(QesSession, :count)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include('id' => session.id, 'state' => 'completed',
                                            'value' => session.value_token)
  end

  it 'returns 410 for an expired token' do
    _session, _submitter = create_qes_session(token: 'expired', expires_at: 1.minute.ago)

    get '/qes/sessions/expired'

    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('expired_token')
  end

  it 'returns 410 for a used token' do
    create_qes_session(state: 'failed', token: 'used')

    get '/qes/sessions/used'

    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('used_token')
  end

  it 'opens the session and returns the payload without data_to_sign' do
    session, submitter = create_qes_session(token: 'open')

    get '/qes/sessions/open'

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('app_opened')
    expect(response.parsed_body['requires_certificate']).to be true
    expect(response.parsed_body).not_to have_key('document_digest')
    expect(response.parsed_body).not_to have_key('data_to_sign')
    expect(session.reload.app_opened_at).to be_present
    expect(response.parsed_body['signer_name']).to eq(submitter.name)
  end

  it 'rejects a certificate chain that is too long' do
    session, _submitter = create_qes_session(token: 'long-chain')
    chain = Array.new(Qes::ControllerConcern::MAX_CHAIN + 1) do
      Base64.strict_encode64(pkcs.ca_certs.first.to_der)
    end

    post '/qes/sessions/long-chain/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain:,
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.state).to eq('awaiting_app')
  end

  it 'rejects an oversized certificate' do
    session, _submitter = create_qes_session(token: 'big-cert')

    post '/qes/sessions/big-cert/certificate', params: {
      certificate: Base64.strict_encode64('x' * (Qes::ControllerConcern::MAX_CERTIFICATE_BYTES + 1)),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.state).to eq('awaiting_app')
  end

  it 'rejects a malformed certificate with 422 instead of 500' do
    session, _submitter = create_qes_session(token: 'malformed')

    post '/qes/sessions/malformed/certificate', params: {
      certificate: Base64.strict_encode64('not a certificate'),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.failure_code).to eq('invalid_certificate')
    expect(session.state).to eq('awaiting_app')
  end

  it 'rejects a certificate that is not qualified' do
    _session, _submitter = create_qes_session(token: 'unqualified')
    key, certificate = QesHelpers.self_signed_qc_sscd_certificate
    certificate.extensions = certificate.extensions.reject do |extension|
      [Qes::CertificateInfo::QC_STATEMENTS_OID, 'qcStatements'].include?(extension.oid)
    end
    certificate.sign(key, OpenSSL::Digest.new('SHA256'))
    allow(Qes).to receive(:trust_roots).and_return([certificate])
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)

    post '/qes/sessions/unqualified/certificate', params: {
      certificate: Base64.strict_encode64(certificate.to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('not_qualified')
  end

  it 'rejects a QcSSCD certificate from the phone keystore' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    _session, _submitter = create_qes_session(token: 'qscd')

    post '/qes/sessions/qscd/certificate', params: {
      certificate: Base64.strict_encode64(QesHelpers.certificate('signer-qscd.crt').to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('level_mismatch')
  end

  it 'requires QcSSCD for a qes field' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    _session, _submitter = create_qes_session(token: 'qes', level: 'qes')

    post '/qes/sessions/qes/certificate', params: {
      certificate: Base64.strict_encode64(QesHelpers.certificate('signer-ades.crt').to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('qes_required_qscd')
  end

  it 'completes the ceremony end to end over HTTP' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'sign')

    get '/qes/sessions/sign'
    expect(response).to have_http_status(:ok)

    post '/qes/sessions/sign/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore',
      app: { platform: 'rspec', version: '1.0.0' }
    }

    expect(response).to have_http_status(:ok)
    expect(session.reload.document_digest).to be_present

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/sign/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
    expect(response.parsed_body['level']).to eq('ades')
    expect(session.reload.state).to eq('completed')
    expect(session.signed_document).to be_attached
  end

  it 'does not complete when a timestamp is required but the TSA URL is missing' do
    session, _submitter = create_qes_session(token: 'required-tsa')
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    post '/qes/sessions/required-tsa/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }
    expect(response).to have_http_status(:ok)
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'),
                              Base64.strict_decode64(response.parsed_body['data_to_sign']))
    Qes::Config[:tsa_required] = true

    post '/qes/sessions/required-tsa/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('tsa_unavailable')
    expect(session.reload.state).not_to eq('completed')
    expect(session.final_document).not_to be_attached
  end

  it 'reports a clear configuration error when the TSA URL has no trust roots' do
    session, _submitter = create_qes_session(token: 'unconfigured-tsa-trust')
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    post '/qes/sessions/unconfigured-tsa-trust/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }
    expect(response).to have_http_status(:ok)
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'),
                              Base64.strict_decode64(response.parsed_body['data_to_sign']))
    Qes::Config[:tsa_url] = 'http://tsa.test'

    post '/qes/sessions/unconfigured-tsa-trust/complete', params: {
      signature: Base64.strict_encode64(signature)
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('tsa_trust_not_configured')
    expect(response.parsed_body['message']).to include('QES_TSA_TRUST_ROOTS')
    expect(session.reload.state).not_to eq('completed')
    expect(session.final_document).not_to be_attached
  end

  it 'stores revocation data in DSS instead of the CMS' do
    session, _submitter = create_qes_session(token: 'big-ltv')
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    allow(Qes::Ltv).to receive(:fetch_crls).and_return([crl])

    post '/qes/sessions/big-ltv/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:ok)

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/big-ltv/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')

    tbs = HexaPDF::Document.new(io: StringIO.new(session.reload.tbs_document.download))
    reserve = tbs.signatures.to_a.last[:Contents].to_s.bytesize

    expect(reserve).to be < 100_000
    expect(session.reload.final_document).to be_attached

    dss = HexaPDF::Document.new(io: StringIO.new(session.reload.final_document.download)).catalog[:DSS]

    expect(dss[:CRLs].map { |ref| ref.stream.to_s }).to include(crl.to_der)
  end

  it 'returns the signature summary for a completed session' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'summary')

    get '/qes/sessions/summary'

    post '/qes/sessions/summary/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/summary/complete', params: { signature: Base64.strict_encode64(signature) }

    get "/s/#{session.submitter.slug}/qes_sessions/#{session.id}", headers: { 'Accept' => 'application/json' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['summary_html']).to include("data-qes-summary=\"#{session.id}\"")
    expect(response.parsed_body['summary_html']).to include(pkcs.certificate.subject.to_s)
    # V poli dokumentu je zkrácená varianta (bez issuer/serial a auditu).
    expect(response.parsed_body['summary_html']).to include('bg-base-200/80')
    expect(response.parsed_body['summary_html']).not_to include('Certificate issuer')
  end

  it 'shows the signature summary for a previous signer in the signing form' do
    QesHelpers.with_crl_server do
      submission = QesHelpers.build_qes_submission(count: 2)
      first, second = submission.submitters.order(:id).to_a
      field = Qes.template_fields(submission).find do |f|
        f['submitter_uuid'] == first.uuid && f['type'] == 'qes'
      end
      session = create(:qes_session, submitter: first, submission:, field_uuid: field['uuid'],
                                     account: submission.account)

      Qes::Providers::Mock.new(session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                        password: 'test').sign!(first, field)
      first.update!(values: first.values.merge(field['uuid'] => session.reload.value_token),
                    completed_at: Time.current)

      get "/s/#{second.slug}"

      expect(response).to have_http_status(:ok)
      expect(response.body).to include("data-qes-summary=\"#{session.id}\"")
      expect(response.body).to include('bg-base-200/80')
    end
  end

  it 'rejects a self-signed QcSSCD certificate that does not chain to a trust root' do
    _session, _submitter = create_qes_session(token: 'selfsigned', level: 'qes')
    _key, cert = QesHelpers.self_signed_qc_sscd_certificate
    expect(Qes::Ltv).not_to receive(:fetch_crls)

    post '/qes/sessions/selfsigned/certificate', params: {
      certificate: Base64.strict_encode64(cert.to_der),
      chain: [],
      key_location: 'card'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('not_trusted')
  end

  it 'validates the certificate chain before fetching its CRLs' do
    create_qes_session(token: 'chain-first')
    verified = false
    allow(Qes::Validator).to receive(:verify_chain!).and_wrap_original do |original, *args|
      original.call(*args)
      verified = true
      nil
    end
    expect(Qes::Ltv).to receive(:fetch_crls) do
      expect(verified).to be true
      [QesHelpers.crl]
    end

    post '/qes/sessions/chain-first/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) }
    }

    expect(response).to have_http_status(:ok)
  end

  it 'clears the failure code when a rejected certificate is followed by a valid one' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'retry-cert')
    _key, bad_cert = QesHelpers.self_signed_qc_sscd_certificate

    post '/qes/sessions/retry-cert/certificate', params: {
      certificate: Base64.strict_encode64(bad_cert.to_der), chain: [], key_location: 'card'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(session.reload.failure_code).to eq('not_trusted')

    post '/qes/sessions/retry-cert/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:ok)
    expect(session.reload.failure_code).to be_nil
  end

  it 'keeps the failure code from the app on abort' do
    session, _submitter = create_qes_session(token: 'abort')

    post '/qes/sessions/abort/abort', params: { code: 'network_error', message: 'offline' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('failed')
    expect(session.reload.failure_code).to eq('network_error')
    expect(session.failure_message).to eq('offline')
  end

  it 'rejects a second complete with a different signature' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'twice-different')

    get '/qes/sessions/twice-different'

    post '/qes/sessions/twice-different/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice-different/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response.parsed_body['state']).to eq('completed')

    other_key = OpenSSL::PKey::RSA.new(2048)
    other_signature = other_key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice-different/complete', params: { signature: Base64.strict_encode64(other_signature) }

    expect(response).to have_http_status(:conflict)
    expect(response.parsed_body['error']).to eq('wrong_state')
    expect(session.reload.signature).to eq(signature)
  end

  it 'is idempotent when complete is called twice' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'twice')

    get '/qes/sessions/twice'

    post '/qes/sessions/twice/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response.parsed_body['state']).to eq('completed')

    post '/qes/sessions/twice/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
    expect(session.reload.state).to eq('completed')
  end

  it 'rejects a foreign signature' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    session, _submitter = create_qes_session(token: 'foreign')

    get '/qes/sessions/foreign'

    post '/qes/sessions/foreign/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    other_key = OpenSSL::PKey::RSA.new(2048)
    signature = other_key.sign(OpenSSL::Digest.new('SHA256'), OpenSSL::Random.random_bytes(16))

    post '/qes/sessions/foreign/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('signature_invalid')
    expect(session.reload.state).to eq('failed')
  end

  it 'cancels the session from the app' do
    session, _submitter = create_qes_session(token: 'abort')

    post '/qes/sessions/abort/abort', params: { code: 'user_cancelled' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('cancelled')
    expect(session.reload.state).to eq('cancelled')
  end

  it 'rate limits after too many failed token attempts' do
    11.times { get '/qes/sessions/unknown' }

    expect(response).to have_http_status(:too_many_requests)
    expect(response.parsed_body['error']).to eq('rate_limited')
  end
  it 'includes current form values in the stored TBS before awaiting_signature' do
    session, submitter = create_qes_session(token: 'snapshot')
    field = Qes.template_fields(submitter.submission).find { |f| f['type'] == 'text' }
    submitter.update!(values: { field['uuid'] => 'Agreed contract value' })
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)

    post '/qes/sessions/snapshot/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) }
    }

    expect(response).to have_http_status(:ok)
    expect(session.reload.state).to eq('awaiting_signature')
    text = Pdfium::Document.open_io(StringIO.new(session.tbs_document.download)) do |pdf|
      (0...pdf.page_count).map { |index| pdf.get_page(index).text }.join("\n")
    end
    expect(text).to include('Agreed contract value')
    expect(session.tbs_document.blob.metadata['qes_values']).to eq(field['uuid'] => 'Agreed contract value')

    submitter.update!(values: { field['uuid'] => 'Changed while signing' })
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)
    post '/qes/sessions/snapshot/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('values_changed')
    expect(session.reload.state).not_to eq('completed')
  end
  %w[expired cancelled].each do |terminal_state|
    it "does not overwrite a #{terminal_state} session when a concurrent request fails" do
      session, _submitter = create_qes_session(token: "race-#{terminal_state}")
      session.update!(state: 'awaiting_signature')
      allow_any_instance_of(Qes::Providers::MobileApp).to receive(:complete!) do
        QesSession.where(id: session.id).update_all(state: terminal_state)
        raise Qes::ClientError.new(:signature_invalid)
      end

      post "/qes/sessions/race-#{terminal_state}/complete",
           params: { signature: Base64.strict_encode64('bad') }

      expect(response).to have_http_status(:unprocessable_content)
      expect(session.reload.state).to eq(terminal_state)
      expect(session.failure_code).to be_nil
      expect(session.failed_at).to be_nil
    end
  end

  it 'does not overwrite completion when a concurrent request fails' do
    session, _submitter = create_qes_session(token: 'race')
    session.update!(state: 'awaiting_signature')
    allow_any_instance_of(Qes::Providers::MobileApp).to receive(:complete!) do
      QesSession.where(id: session.id).update_all(state: 'completed', completed_at: Time.current)
      raise Qes::ClientError.new(:signature_invalid)
    end

    post '/qes/sessions/race/complete', params: { signature: Base64.strict_encode64('bad') }

    expect(response).to have_http_status(:unprocessable_content)
    expect(session.reload.state).to eq('completed')
    expect(session.failure_code).to be_nil
    expect(session.failed_at).to be_nil
  end
end
