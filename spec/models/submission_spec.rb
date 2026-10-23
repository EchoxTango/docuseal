# frozen_string_literal: true

require 'rails_helper'

# Vynucení striktního pořadí u QES šablon (SPEC § 4.6).
RSpec.describe Submission do
  def build_template!(**options)
    account = create(:account)
    user = create(:user, account:)

    create(:template, account:, author: user, **options)
  end

  it 'forces preserved order for a template with a qes field' do
    template = QesHelpers.build_qes_submission(count: 2).template
    submission = create(:submission, template:, account: template.account, submitters_order: 'random')

    expect(submission.reload.submitters_order).to eq('preserved')
  end

  it 'keeps random order for a template without qes fields' do
    template = build_template!
    submission = create(:submission, template:, account: template.account, submitters_order: 'random')

    expect(submission.reload.submitters_order).to eq('random')
  end
end
