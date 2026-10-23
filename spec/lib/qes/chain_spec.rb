# frozen_string_literal: true

require 'rails_helper'

# Řetězení QES podpisů (SPEC § 4.6, § 7.1): druhý signer podepisuje finální
# PDF prvního jako novou inkrementální revizi; předchozí podpisy zůstávají INTACT.
RSpec.describe 'QES chained signatures' do
  before do
    QesHelpers.configure!
    Qes::Config[:seal_pkcs_path] = QesHelpers.pki_path('signer-ades.p12').to_s
    Qes::Config[:seal_pkcs_password] = 'test'
  end

  def sign!(submission, index, field_index: 0, complete: true)
    submitter = submission.submitters.order(:id).to_a[index]
    field = Qes.template_fields(submission).select do |f|
      f['submitter_uuid'] == submitter.uuid && f['type'] == 'qes'
    end[field_index]
    session = create(:qes_session, submitter:, submission:, field_uuid: field['uuid'],
                                   account: submission.account)
    provider = Qes::Providers::Mock.new(session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                                password: 'test')

    provider.sign!(submitter, field)
    submitter.update!(completed_at: Time.current) if complete
    submission.reload

    [submission.submitters.order(:id).to_a[index], session.reload]
  end

  it 'chains the next TBS on the previous final document and keeps all signatures intact' do
    QesHelpers.with_crl_server do
      submission = QesHelpers.build_qes_submission(count: 2)

      first, first_session = sign!(submission, 0)
      _second, second_session = sign!(submission, 1)

      first_final = first_session.final_document.download
      second_tbs = second_session.tbs_document.download
      second_final = second_session.final_document.download

      # Druhá revize začíná přesně prvním finálním PDF (žádná přestavba stránek).
      expect(second_tbs.byteslice(0, first_final.bytesize)).to eq(first_final)

      report = Qes::Validator.call(second_final, trust_roots: QesHelpers.trust_roots)

      expect(report[:intact]).to be true
      expect(report[:trusted]).to be true
      expect(report[:coverage]).to eq('full')
      expect(report[:signatures].size).to eq(4)

      # První session zůstává platná (podpis appky + pečeť).
      expect(HexaPDF::Document.new(io: StringIO.new(first_final)).signatures.to_a.size).to eq(2)
    end
  end

  it 'lets the same submitter sign twice with the same certificate' do
    QesHelpers.with_crl_server do
      submission = QesHelpers.build_qes_submission(qes_fields_per_submitter: 2)
      submitter = submission.submitters.order(:id).first
      fields = Qes.template_fields(submission).select do |f|
        f['submitter_uuid'] == submitter.uuid && f['type'] == 'qes'
      end

      _first, first_session = sign!(submission, 0, field_index: 0, complete: false)
      _second, second_session = sign!(submission, 0, field_index: 1, complete: false)

      first_final = first_session.final_document.download
      second_tbs = second_session.tbs_document.download
      second_final = second_session.final_document.download

      # Druhý TBS navazuje na první finální PDF téhož podepisujícího.
      expect(second_tbs.byteslice(0, first_final.bytesize)).to eq(first_final)

      report = Qes::Validator.call(second_final, trust_roots: QesHelpers.trust_roots)

      expect(report[:intact]).to be true
      expect(report[:coverage]).to eq('full')
      expect(report[:signatures].size).to eq(4)

      expect(submitter.reload.values.values_at(*fields.map { |f| f['uuid'] })).to eq(
        [first_session.reload.value_token, second_session.reload.value_token]
      )

      # Výsledný dokument podepisujícího je poslední revize se všemi podpisy.
      submitter.update!(completed_at: Time.current)
      documents = Qes::ResultAttachments.call(submitter)

      expect(documents.map(&:download).join).to eq(second_final)
    end
  end

  it 'draws values and the stamp on the globally indexed page for multiple attachments' do
    QesHelpers.with_crl_server do
      submission = QesHelpers.build_qes_submission(count: 2, attachment_count: 2, field_types: [],
                                                  qes_attachment_index: 1)

      _first, first_session = sign!(submission, 0)
      _second, second_session = sign!(submission, 1)

      first_attachment, second_attachment = submission.template_schema.pluck('attachment_uuid')

      expect(Qes::TbsDocument.page_offsets(submission)).to eq(
        first_attachment => 0, second_attachment => 1
      )

      base = HexaPDF::Document.new(io: StringIO.new(first_session.final_document.download))
      tbs = HexaPDF::Document.new(io: StringIO.new(second_session.tbs_document.download))

      # Pečeť druhého signera se kreslí na globální stránku 1 (druhá příloha).
      expect(Array(tbs.pages[1][:Contents]).size).to be > Array(base.pages[1][:Contents]).size
      expect(Array(tbs.pages[0][:Contents]).size).to eq(Array(base.pages[0][:Contents]).size)
    end
  end
end
