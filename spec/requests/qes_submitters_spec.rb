# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'QES API submitter completion', type: :request do
  before { QesHelpers.configure! }

  let(:submission) { QesHelpers.build_qes_submission(qes_fields_per_submitter: 2) }
  let(:submitter) { submission.submitters.first }
  let(:fields) { Qes.template_fields(submission).select { |field| field['type'] == 'qes' } }
  let(:headers) { { 'x-auth-token' => submission.template.author.access_token.token } }

  def complete_submitter
    put "/api/submitters/#{submitter.id}", params: { completed: true }, headers:, as: :json
  end

  it 'returns 422 without changing completion when required sessions are missing' do
    complete_submitter

    expect(response).to have_http_status(:unprocessable_content)
    expect(submitter.reload.completed_at).to be_nil
  end

  it 'requires a completed session for every required field' do
    create(:qes_session, :with_values_snapshot, submitter:, field_uuid: fields.first['uuid'], state: 'completed', level: 'ades')
    create(:qes_session, :with_values_snapshot, submitter:, field_uuid: fields.last['uuid'], state: 'awaiting_signature', level: 'ades')

    complete_submitter

    expect(response).to have_http_status(:unprocessable_content)
    expect(submitter.reload.completed_at).to be_nil
  end

  it 'accepts completed sessions bound to every required field' do
    fields.each do |field|
      create(:qes_session, :with_values_snapshot, submitter:, field_uuid: field['uuid'], state: 'completed', level: 'ades')
    end

    complete_submitter

    expect(response).to have_http_status(:ok)
    expect(submitter.reload.completed_at).to be_present
  end

  it 'rejects sessions whose level does not satisfy the field' do
    fields.each do |field|
      create(:qes_session, :with_values_snapshot, submitter:, field_uuid: field['uuid'], state: 'completed', level: 'none')
    end

    complete_submitter

    expect(response).to have_http_status(:unprocessable_content)
    expect(submitter.reload.completed_at).to be_nil
  end

  it 'preserves completion for templates without QES fields' do
    submission.update!(template_fields: Qes.template_fields(submission).reject { |field| field['type'] == 'qes' })

    complete_submitter

    expect(response).to have_http_status(:ok)
    expect(submitter.reload.completed_at).to be_present
  end
  [false, nil, 'false', '0', 'off'].each do |completed|
    it "updates values without completing for #{completed.inspect}" do
      text = Qes.template_fields(submission).find { |field| field['type'] == 'text' }
      put "/api/submitters/#{submitter.id}",
          params: { completed:, values: { text['uuid'] => 'Updated text' } }, headers:, as: :json

      expect(response).to have_http_status(:ok)
      expect(submitter.reload.completed_at).to be_nil
      expect(submitter.values[text['uuid']]).to eq('Updated text')
    end
  end

  it 'requires QES for a string true completion flag' do
    put "/api/submitters/#{submitter.id}", params: { completed: 'true' }, headers:, as: :json

    expect(response).to have_http_status(:unprocessable_content)
    expect(submitter.reload.completed_at).to be_nil
  end

  it 'does not complete for string false without QES either' do
    submission.update!(template_fields: Qes.template_fields(submission).reject { |field| field['type'] == 'qes' })
    put "/api/submitters/#{submitter.id}", params: { completed: 'false' }, headers:, as: :json

    expect(response).to have_http_status(:ok)
    expect(submitter.reload.completed_at).to be_nil
  end

  it 'rejects API value changes after certificate signing' do
    field = Qes.template_fields(submission).find { |item| item['type'] == 'text' }
    submitter.update!(values: { field['uuid'] => 'Signed value' })
    create(:qes_session, :with_values_snapshot, submitter:, field_uuid: fields.first['uuid'], state: 'completed', level: 'ades')

    put "/api/submitters/#{submitter.id}", params: { values: { field['uuid'] => 'Different value' } },
                                         headers:, as: :json

    expect(response).to have_http_status(:unprocessable_content)
    expect(submitter.reload.values[field['uuid']]).to eq('Signed value')
  end
end
