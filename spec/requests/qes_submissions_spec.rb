# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'QES API submission creation', type: :request do
  before { QesHelpers.configure! }

  let(:existing) { QesHelpers.build_qes_submission(qes_fields_per_submitter: 2) }
  let(:template) { existing.template }
  let(:headers) { { 'X-Auth-Token' => template.author.access_token.token } }

  def create_completed(values: {})
    post "/api/templates/#{template.id}/submissions", headers:, as: :json, params: {
      send_email: false,
      submitters: [{ email: 'signer@example.test', role: template.submitters.first['name'],
                     completed: true, values: }]
    }
  end

  it 'returns 422 without creating or publishing a completed submission without required sessions' do
    template
    expect(ProcessSubmitterCompletionJob).not_to receive(:perform_async)
    expect { create_completed }.not_to change(Submission, :count)
    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('Required QES signatures are missing')
  end

  it 'rejects a foreign session token even when the QES fields are optional' do
    fields = template.fields.deep_dup
    fields.select { |field| field['type'] == 'qes' }.each { |field| field['required'] = false }
    template.update!(fields:)
    first, second = fields.select { |field| field['type'] == 'qes' }
    session = create(:qes_session, submitter: existing.submitters.first, field_uuid: first['uuid'],
                                   state: 'completed', level: 'ades')
    expect(Qes::ValueValidator).to receive(:call).and_call_original
    expect(ProcessSubmitterCompletionJob).not_to receive(:perform_async)
    expect { create_completed(values: { second['uuid'] => session.value_token }) }
      .not_to change(Submission, :count)
    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('Invalid qes field value')
  end

  it 'preserves completed creation for templates without QES' do
    template.update!(fields: template.fields.reject { |field| field['type'] == 'qes' })
    create_completed
    expect(response).to have_http_status(:ok)
    expect(template.submissions.order(:id).last.submitters.first.completed_at).to be_present
  end
end
