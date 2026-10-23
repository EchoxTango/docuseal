# frozen_string_literal: true

module Api
  # Ověření PDF (docs/16): `create` je stateless, `store` navíc uloží PDF do
  # složky „Verified documents“ jako běžný DocuSeal template (Documents).
  class QesVerificationsController < ApiBaseController
    include Qes::ControllerConcern

    skip_authorization_check

    rescue_from ActiveRecord::RecordInvalid, with: :render_storage_error
    rescue_from HexaPDF::Error, Pdfium::PdfiumError, with: :render_invalid_pdf

    def create
      _data, report = verify_upload

      render json: report.merge(stored: false)
    end

    def store
      data, report = verify_upload
      template = Qes::VerifiedDocuments.store!(report, data, account: current_account,
                                                              user: current_user,
                                                              name: Qes::PdfUpload.file_name(params))

      render json: report.merge(stored: true, template_id: template.id,
                               folder: Qes::VerifiedDocuments::FOLDER_NAME)
    end

    private

    def verify_upload
      Qes::RateLimiter.check!(request.remote_ip)

      data = Qes::PdfUpload.upload_data(params, allow_signed: true)

      [data, Qes::Verifier.call(data, name: Qes::PdfUpload.file_name(params),
                                      account: current_account)]
    end

    def render_storage_error(error)
      render json: { error: 'storage_failed', message: error.message }, status: :unprocessable_content
    end

    def render_invalid_pdf(error)
      render json: { error: 'invalid_pdf', message: error.message }, status: :unprocessable_content
    end
  end
end
