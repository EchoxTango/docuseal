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
end
