# frozen_string_literal: true

module Submissions
  module GenerateCombinedAttachment
    module_function

    def call(submitter, with_audit: true)
      return Qes::ResultAttachments.combined_document(submitter, with_audit:) if submitter.qes_sessions.completed.exists?

      pdf = build_combined_pdf(submitter, with_audit:)

      submission = submitter.submission
      account = submission.account

      pkcs = Accounts.load_signing_pkcs(account)
      tsa_url = Accounts.load_timeserver_url(account)

      io = StringIO.new

      pdf.trailer.info[:Creator] = "#{Docuseal.product_name} (#{Docuseal::PRODUCT_URL})"

      if Docuseal.pdf_format == 'pdf/a-3b'
        pdf.task(:pdfa, level: '3b')
        pdf.config['font.map'] = GenerateResultAttachments::PDFA_FONT_MAP
      end

      if pkcs
        sign_params = {
          reason: Submissions::GenerateResultAttachments.single_sign_reason(submitter),
          **Submissions::GenerateResultAttachments.build_signing_params(submitter, pkcs, tsa_url)
        }

        sign_pdf(io, pdf, sign_params)

        Submissions::GenerateResultAttachments.maybe_enable_ltv(io, sign_params)
      else
        pdf.write(io, incremental: true, validate: true)
      end

      Qes::ResultAttachments.attach_pdf(
        submission, io.tap(&:rewind).string,
        name: with_audit ? 'combined_document' : 'merged_document'
      )
    end

    def sign_pdf(io, pdf, sign_params)
      pdf.sign(io, **sign_params)
    rescue HexaPDF::MalformedPDFError, NoMethodError => e
      Rollbar.error(e) if defined?(Rollbar)

      pdf.sign(io, write_options: { incremental: false }, **sign_params)
    rescue HexaPDF::Error => e
      Rollbar.error(e) if defined?(Rollbar)

      pdf.validate(auto_correct: true)

      pdf.sign(io, write_options: { validate: false }, **sign_params)
    end

    def build_combined_pdf(submitter, with_audit:)
      pdfs_index = Submissions::GenerateResultAttachments.generate_pdfs(submitter)

      if with_audit
        audit_trail = I18n.with_locale(submitter.account.locale) do
          Submissions::GenerateAuditTrail.build_audit_trail(submitter.submission)
        end

        audit_trail.dispatch_message(:complete_objects)
      end

      result = HexaPDF::Document.new

      # `template_schema` je nil u submissionu vytvořeného přes API (doplní se
      # až otevřením formuláře); stejný fallback jako `Qes.template_schema`.
      schema = submitter.submission.template_schema.presence || submitter.submission.template&.schema || []

      schema.each do |item|
        pdf = pdfs_index[item['attachment_uuid']]

        next unless pdf

        pdf.dispatch_message(:complete_objects)

        pdf.pages.each { |page| result.pages << result.import(page) }
      end

      audit_trail&.pages&.each { |page| result.pages << result.import(page) }

      result
    end
  end
end
