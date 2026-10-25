# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::ValueValidator do
  before { QesHelpers.configure! }

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:field) { submitter.submission.template_fields.find { |f| f['type'] == 'qes' } }

  it 'accepts qes:<id> of a completed session of the same submitter' do
    session = create(:qes_session, submitter:, submission: submitter.submission,
                                    account: submitter.account, field_uuid: field['uuid'],
                                    state: 'completed')

    expect { described_class.call({ field['uuid'] => session.value_token }, submitter) }.not_to raise_error
  end

  it 'rejects an arbitrary value' do
    expect { described_class.call({ field['uuid'] => 'signed' }, submitter) }
      .to raise_error(Submitters::SubmitValues::ValidationError)
  end

  it 'rejects a session of another submitter' do
    session = create(:qes_session, state: 'completed')

    expect { described_class.call({ field['uuid'] => session.value_token }, submitter) }
      .to raise_error(Submitters::SubmitValues::ValidationError)
  end

  it 'rejects an incomplete session' do
    session = create(:qes_session, submitter:, submission: submitter.submission,
                                    account: submitter.account, field_uuid: field['uuid'],
                                    state: 'awaiting_signature')

    expect { described_class.call({ field['uuid'] => session.value_token }, submitter) }
      .to raise_error(Submitters::SubmitValues::ValidationError)
  end
  context 'after signing a document snapshot' do
    let(:text_field) { Qes.template_fields(submitter.submission).find { |f| f['type'] == 'text' } }

    before do
      submitter.update!(values: { text_field['uuid'] => 'Agreed price' })
      session = create(:qes_session, submitter:, state: 'completed')
      session.tbs_document.attach(io: StringIO.new('%PDF-snapshot'), filename: 'snapshot.pdf',
                                  content_type: 'application/pdf',
                                  metadata: { qes_values: { text_field['uuid'] => 'Agreed price' } })
    end

    it 'rejects a later change through SubmitValues without persisting it' do
      params = ActionController::Parameters.new(values: { text_field['uuid'] => 'Different price' })

      expect { Submitters::SubmitValues.update_submitter!(submitter, params, nil) }
        .to raise_error(Submitters::SubmitValues::ValidationError, 'Signed field values cannot be changed')
      expect(submitter.reload.values[text_field['uuid']]).to eq('Agreed price')
    end

    it 'allows resubmitting the signed value' do
      params = ActionController::Parameters.new(values: { text_field['uuid'] => 'Agreed price' })

      expect { Submitters::SubmitValues.update_submitter!(submitter, params, nil) }.not_to raise_error
    end
  end
  it 'checks effective values as well as the submitted values' do
    text_field = Qes.template_fields(submitter.submission).find { |f| f['type'] == 'text' }
    submitter.update!(values: { text_field['uuid'] => 'Signed value' })
    create(:qes_session, submitter:, state: 'completed')
    submitter.values[text_field['uuid']] = 'Changed by completion defaults'

    expect { described_class.call({ text_field['uuid'] => 'Signed value' }, submitter) }
      .to raise_error(Submitters::SubmitValues::ValidationError)
  end
end
