# frozen_string_literal: true

module Qes
  # Uložení ověřeného PDF do uživatelsky viditelné složky „Verified documents“
  # (docs/16). Využívá standardní DocuSeal template + dokument, takže uživatel
  # vidí soubor v Documents, může ho stáhnout, sdílet i smazat. Report ověření
  # zůstává v `template.preferences['qes_verification']` (JSON).
  module VerifiedDocuments
    FOLDER_NAME = 'Verified documents'
    REPORT_KEY = 'qes_verification'

    module_function

    def store!(report, data, account:, user:, name:)
      unless report[:intact] && !report[:modified]
        raise ClientError.new(:not_verifiable, 'Only intact documents can be stored')
      end

      template = account.templates.new(
        name:,
        author: user,
        source: :api,
        submitters: [],
        fields: [],
        preferences: { REPORT_KEY => report.merge(stored_at: Time.current.utc.iso8601) }
      )
      template.folder = TemplateFolders.find_or_create_by_name(user, FOLDER_NAME)
      template.save!

      documents, = Templates::CreateAttachments.call(
        template, { files: [Qes::PdfUpload.uploaded_file(data, name, prefix: 'qes-verified-document')] }
      )
      document = documents.first

      template.update!(schema: [{ 'attachment_uuid' => document.uuid,
                                 'name' => document.filename.base }])

      template
    end
  end
end
