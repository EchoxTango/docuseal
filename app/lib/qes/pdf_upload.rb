# frozen_string_literal: true

module Qes
  # Validace nahrávaného PDF (docs/15 § 5.1, docs/16): stejná pravidla pro
  # přímý podpis i ověření PDF, aby se nezměnila jen na jednom místě (M3).
  module PdfUpload
    module_function

    def upload_data(params, allow_signed: false)
      file = params[:file]

      raise Qes::ClientError.new(:invalid_pdf, 'Missing PDF file') unless file.respond_to?(:read)

      data = file.read.to_s

      if data.bytesize > Qes::Config[:pdf_max_bytes].to_i
        raise Qes::ClientError.new(:file_too_large, 'PDF file is too large')
      end

      unless data.start_with?('%PDF-') && file.content_type.to_s == 'application/pdf'
        raise Qes::ClientError.new(:invalid_pdf, 'Not a PDF file')
      end

      Qes::PdfSource.validate!(data, allow_signed:)

      data
    end

    def file_name(params)
      params[:file].original_filename.presence || 'document.pdf'
    end

    def uploaded_file(data, name, prefix: 'qes-document')
      tempfile = Tempfile.new([prefix, '.pdf'])
      tempfile.binmode
      tempfile.write(data)
      tempfile.rewind

      ActionDispatch::Http::UploadedFile.new(tempfile:, filename: name, type: 'application/pdf')
    end
  end
end
