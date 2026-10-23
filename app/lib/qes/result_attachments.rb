# frozen_string_literal: true

module Qes
  # Hook do generování PDF (SPEC § 7.7): místo přestavby stránek se použije
  # finální podepsané PDF (kritérium hotovo: podpis zůstává platný).
  module ResultAttachments
    module_function

    # Nahrazuje GenerateResultAttachments.call pro QES submission: vytvoří
    # `documents` z `final_document` (bez dalšího podepisování a bez importu stránek).
    def call(submitter)
      session = completed_session(submitter)
      return [] if session.nil? || !session.final_document.attached?

      ActiveStorage::Attachment.create!(
        blob: session.final_document.blob,
        name: 'documents',
        record: submitter,
        metadata: {
          original_uuid: attachment_uuid(session),
          analyzed: true,
          sha256: sha256_of(session)
        }
      )

      submitter.documents.reload
    end

    # Combined/merged dokument pro QES submission: kopie final_document bez
    # `sign_pdf` a bez přidání auditní stránky (obojí by zneplatnilo podpis).
    def combined_document(submitter, with_audit: true)
      session = completed_session(submitter)

      return [] if session.nil? || !session.final_document.attached?

      # Blob se znovu používá (ne kopie PDF): u 10 MB PDF to je 10 MB navíc.
      attach_blob(submitter.submission, session.final_document.blob,
                  name: with_audit ? 'combined_document' : 'merged_document')
    end

    # `final_pdf_sha256` je hex; metadata `sha256` je base64url (bez stahování PDF).
    def sha256_of(session)
      digest = session.final_pdf_sha256.presence || Digest::SHA256.hexdigest(session.final_document.download)

      Base64.urlsafe_encode64([digest].pack('H*'))
    end

    # Příloha se stejným blobem (bez kopie PDF).
    def attach_blob(submission, blob, name:)
      ActiveStorage::Attachment.create!(blob:, name:, record: submission)
    end

    # Společné vytvoření blobu a přílohy (stejné jako v `GenerateCombinedAttachment`).
    def attach_pdf(submission, bytes, name:)
      ActiveStorage::Attachment.create!(
        blob: ActiveStorage::Blob.create_and_upload!(
          io: StringIO.new(bytes),
          filename: "#{submission.name || submission.template&.name}.pdf".tr('/', '-')
        ),
        name:,
        record: submission
      )
    end

    def completed_session(submitter)
      submitter.qes_sessions.completed.order(:id).last
    end

    # `original_uuid` musí být uuid přílohy, na které je pole `qes` (ne uuid pole):
    # `build_pdfs_index` podle něj hledá základ pro dalšího signera (SPEC § 4.6).
    def attachment_uuid(session)
      session.field&.dig('areas', 0, 'attachment_uuid') || session.field_uuid
    end
  end
end
