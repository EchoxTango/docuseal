# frozen_string_literal: true

FactoryBot.define do
  factory :qes_session do
    submitter { QesHelpers.build_qes_submitter }

    account { submitter.account }
    submission { submitter.submission }
    field_uuid { submitter.submission.template_fields.find { |f| f['type'] == 'qes' }['uuid'] }
    expires_at { 10.minutes.from_now }
    token_digest { SecureRandom.hex(32) }

    trait :with_values_snapshot do
      after(:create) do |session|
        session.tbs_document.attach(
          io: StringIO.new('%PDF-snapshot'), filename: 'snapshot.pdf', content_type: 'application/pdf',
          metadata: {
            qes_values: Qes::ValueValidator.non_qes_values(session.submitter.values, session.submitter),
            qes_document_manifest: Qes::TbsDocument.manifest_for(session.submitter.submission)
          }
        )
      end
    end
  end
end
