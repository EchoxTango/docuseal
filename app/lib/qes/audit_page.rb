# frozen_string_literal: true

module Qes
  # Stránka QES v audit trailu (SPEC § 13): certifikát, čas, hashe, úroveň,
  # validace a stav pečeti. Auditní stránka je v samostatném artefaktu.
  module AuditPage
    module_function

    def append(composer, submission)
      sessions = submission.submitters.flat_map { |s| s.qes_sessions.completed.order(:id).to_a }
      return if sessions.empty?

      composer.new_page

      composer.text(I18n.t('qes.audit.title'), font_size: 16, padding: [0, 0, 15, 0])

      sessions.each do |session|
        composer.text(session.submitter.name.to_s, font_size: 12, padding: [0, 0, 6, 0])
        composer.table(rows_for(session), cell_style: { padding: [0, 0, 6, 0], border: { width: 0 } })
        composer.text("\n")
      end
    end

    def rows_for(session)
      info = session.certificate_info || {}
      report = session.validation_report || {}

      [
        row(I18n.t('qes.audit.field'), session.field&.dig('name').presence || session.field_uuid),
        row(I18n.t('qes.audit.certificate_subject'), info['subject']),
        row(I18n.t('qes.audit.certificate_issuer'), info['issuer']),
        row(I18n.t('qes.audit.certificate_serial'), info['serial']),
        row(I18n.t('qes.audit.level'), session.level.to_s.upcase),
        row(I18n.t('qes.audit.key_location'), session.key_location),
        row(I18n.t('qes.audit.signed_at'), session.completed_at&.utc&.iso8601),
        row(I18n.t('qes.audit.document_digest'), session.document_digest),
        row(I18n.t('qes.audit.signed_pdf_sha256'), session.signed_pdf_sha256),
        row(I18n.t('qes.audit.final_pdf_sha256'), session.final_pdf_sha256),
        row(I18n.t('qes.audit.validation'), validation_text(report)),
        row(I18n.t('qes.audit.seal'), session.seal_state),
        row(I18n.t('qes.audit.protocol'), '1')
      ].compact
    end

    def row(label, value)
      return if value.blank?

      [label, value.to_s]
    end

    def validation_text(report)
      return if report.blank?

      parts = []
      parts << I18n.t('qes.audit.valid') if report['intact']
      parts << I18n.t('qes.audit.trusted') if report['trusted']
      parts << I18n.t('qes.audit.coverage', coverage: report['coverage']) if report['coverage'].present?
      parts.join(', ')
    end
  end
end
