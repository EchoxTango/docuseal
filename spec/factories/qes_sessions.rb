# frozen_string_literal: true

FactoryBot.define do
  factory :qes_session do
    submitter { QesHelpers.build_qes_submitter }

    account { submitter.account }
    submission { submitter.submission }
    field_uuid { submitter.submission.template_fields.find { |f| f['type'] == 'qes' }['uuid'] }
    expires_at { 10.minutes.from_now }
    token_digest { SecureRandom.hex(32) }
  end
end
