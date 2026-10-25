# frozen_string_literal: true

require 'rails_helper'

# Doteky forku ve views (SPEC § 14, docs/18 § 5 M19): plný přehled QES v kartě
# podepisujícího (`submissions/show`) a zkrácený přehled v poli dokumentu
# (`submissions/_value`). Bez testu se rozbitý partial pozná až na stagingu.
RSpec.describe 'QES views' do
  let(:account) { create(:account) }
  let(:author) { create(:user, account:) }
  let(:submitter) { QesHelpers.build_qes_submitter(account:) }
  let(:field) { submitter.submission.template_fields.find { |f| f['type'] == 'qes' } }

  let!(:session) do
    create(:qes_session, submitter:, submission: submitter.submission, account:,
                          field_uuid: field['uuid'], state: 'completed',
                          completed_at: Time.current, level: 'ades',
                          key_location: 'phone_keystore', seal_state: 'applied',
                          certificate_info: { 'subject' => '/C=CZ/O=Test/CN=Jan Novák',
                                              'issuer' => '/C=CZ/O=Test/CN=Test Root CA',
                                              'serial' => '0x1001' },
                          validation_report: { 'intact' => true, 'trusted' => true,
                                               'coverage' => 'full' })
  end

  before do
    QesHelpers.configure!
    sign_in(author)

    submitter.update!(completed_at: Time.current,
                      values: submitter.values.merge(field['uuid'] => "qes:#{session.id}"))
    submitter.submission.update!(completed_at: Time.current)
  end

  it 'renders the full QES summary in the signer card' do
    get submission_path(submitter.submission)

    expect(response).to have_http_status(:ok)
    expect(response.body).to include("data-qes-summary=\"#{session.id}\"")
    expect(response.body).to include('Certificate issuer')
    expect(response.body).to include('Jan Novák')
  end

  it 'renders the compact QES summary in the document field' do
    get submission_path(submitter.submission)

    expect(response.body).to include('bg-base-200/80')
    expect(response.body).not_to include("qes:#{session.id}")
  end

  it 'renders signing, completion, DocTS and validation times in the full summary' do
    session.update!(signing_time: Time.utc(2026, 10, 25, 10), completed_at: Time.utc(2026, 10, 25, 10, 5),
                    doc_timestamp_state: 'applied',
                    validation_report: { intact: true, trusted: true, coverage: 'full',
                                         signer_validation: { time_source: 'timestamp',
                                                              validated_at_time: '2026-10-25T10:04:00Z' },
                                         doc_timestamp: { timestamp_time: '2026-10-25T10:04:30Z' } })

    get submission_path(submitter.submission)

    expect(response).to have_http_status(:ok)
    expect(response.body).to include('Signing time', 'Completed', 'Document timestamp (DocTS)',
                                     'Validation time source', 'Verified timestamp',
                                     '2026-10-25T10:00:00Z', '2026-10-25T10:05:00Z',
                                     '2026-10-25T10:04:00Z', '2026-10-25T10:04:30Z')
  end
end
