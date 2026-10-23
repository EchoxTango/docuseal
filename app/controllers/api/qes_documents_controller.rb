# frozen_string_literal: true

module Api
  # Upload PDF pro přímý podpis (docs/15 § 5.1): založí šablonu ve složce
  # „Direct signing“ s jedním podepisujícím a jedním polem `qes`. Zbytek toku jde
  # přes existující DocuSeal API:
  #
  #   PATCH /api/templates/:id            umístění pečeti (pole.areas)
  #   POST  /api/templates/:id/submissions dokument k podpisu (send_email: false)
  #   POST  /s/:slug/qes_sessions         spuštění obřadu (X-Auth-Token)
  #   PUT   /api/submitters/:id            completed: true → PDF + audit
  #   GET   /api/submissions/:id/documents stažení finálního PDF
  class QesDocumentsController < ApiBaseController
    include Qes::ControllerConcern

    skip_authorization_check

    FOLDER_NAME = 'Direct signing'
    FIELD_NAME = 'Certificate signature'
    FIELD_TYPE = 'qes'
    DEFAULT_LEVEL = 'ades'
    LEVELS = %w[ades qes].freeze

    def create
      Qes::RateLimiter.check!(request.remote_ip)

      data = Qes::PdfUpload.upload_data(params)
      data = Qes::PdfSource.normalize_rotation(data) || data

      template, document = build_template(data)

      render json: payload(template, document, data), status: :created
    end

    private

    def build_template(data)
      template = current_account.templates.new(name: Qes::PdfUpload.file_name(params), author: current_user,
                                             source: :api)
      template.folder = TemplateFolders.find_or_create_by_name(current_user, FOLDER_NAME)
      template.submitters = [{ 'uuid' => SecureRandom.uuid, 'name' => display_name }]
      template.save!

      documents, = Templates::CreateAttachments.call(
        template, { files: [Qes::PdfUpload.uploaded_file(data, Qes::PdfUpload.file_name(params))] }
      )
      document = documents.first

      template.update!(
        schema: [{ 'attachment_uuid' => document.uuid, 'name' => document.filename.base }],
        fields: [field(template)]
      )

      [template, document]
    end

    def field(template)
      {
        'uuid' => SecureRandom.uuid,
        'submitter_uuid' => template.submitters.first['uuid'],
        'name' => FIELD_NAME,
        'type' => FIELD_TYPE,
        'required' => true,
        'preferences' => { 'level' => level_required },
        'areas' => []
      }
    end

    def payload(template, document, data)
      expires_at = Accounts.link_expires_at(current_account)

      {
        template_id: template.id,
        folder: FOLDER_NAME,
        submitter_role: template.submitters.first['name'],
        field: template.fields.first,
        document: {
          uuid: document.uuid,
          filename: document.filename.to_s,
          pages: Qes::PdfSource.page_sizes(data).each_with_index.map do |size, index|
            {
              index:,
              width: size[:width],
              height: size[:height],
              preview_url: preview_url(document, index, expires_at)
            }
          end
        },
        stamp: {
          width: Qes::Stamp::MIN_WIDTH,
          height: Qes::Stamp::MIN_HEIGHT
        }
      }
    end

    def preview_url(document, index, expires_at)
      blob = document.preview_images.joins(:blob)
                     .find_by(blob: { filename: ["#{index}.png", "#{index}.jpg"] })&.blob

      blob && ActiveStorage::Blob.proxy_url(blob, expires_at:)
    end

    def display_name
      params[:display_name].presence || current_user.full_name.presence || current_user.email
    end

    def level_required
      level = params[:level_required].presence || DEFAULT_LEVEL

      raise Qes::ClientError.new(:invalid_level, 'Unsupported signature level') unless level.in?(LEVELS)

      level
    end

  end
end
