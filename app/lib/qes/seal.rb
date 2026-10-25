# frozen_string_literal: true

module Qes
  # Pečeť DocuSealu: druhá inkrementální signatura **až po** podpisu appky
  # (SPEC § 7.6). Podpis appky zůstává INTACT; chybu řeší dokončení obřadu.
  module Seal
    module_function

    def apply(pdf_bytes, account, submitter:, pkcs: nil)
      unless pkcs || Docuseal.multitenant? || Docuseal::CERTS.present? ||
             EncryptedConfig.exists?(key: EncryptedConfig::ESIGN_CERTS_KEY)
        return [pdf_bytes, 'none']
      end

      pkcs ||= Accounts.load_signing_pkcs(account)
      return [pdf_bytes, 'failed'] if pkcs.blank?

      pdf = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))
      io = StringIO.new

      params = {
        reason: Submissions::GenerateResultAttachments.single_sign_reason(submitter),
        **Submissions::GenerateResultAttachments.build_signing_params(
          submitter, pkcs, Accounts.load_timeserver_url(account)
        )
      }

      pdf.sign(io, write_options: { validate: false }, **params)

      [io.string, 'applied']
    rescue StandardError => e
      Rails.logger.error("[qes] seal failed: #{e.class}: #{e.message}")

      [pdf_bytes, 'failed']
    end
  end
end
