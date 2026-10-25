# frozen_string_literal: true

module Qes
  # Společné chování QES controllerů (SPEC § 5): konfigurace, chybové odpovědi,
  # dekódování certifikátů a limity. Bez toho se validace a limity rozcházely
  # mezi endpointy (M3).
  module ControllerConcern
    extend ActiveSupport::Concern

    MAX_CHAIN = 5
    MAX_CERTIFICATE_BYTES = 8_192

    included do
      rescue_from Qes::ClientError, with: :render_qes_error
      rescue_from Qes::InvalidTransition, with: :render_qes_wrong_state

      before_action :ensure_enabled
    end

    private

    def ensure_enabled
      render json: { error: 'disabled' }, status: :not_found unless Qes::Config[:enabled]
    end

    def render_qes_error(error)
      status = error.code == :rate_limited ? :too_many_requests : :unprocessable_content

      if error.is_a?(Qes::SigningValues::IncompleteFields)
        return render json: { error: error.code.to_s, missing_fields: error.missing_fields }, status:
      end

      render_qes_error_with(error.code, status, message: error.message)
    end

    def render_qes_wrong_state(_error)
      render_qes_error_with(:wrong_state, :conflict)
    end

    def render_qes_error_with(code, status, message: nil)
      message ||= I18n.t("qes.error.#{code}", default: code.to_s)

      render json: { error: code.to_s, message: }, status:
    end

    def decode(value, code)
      Base64.strict_decode64(value.to_s)
    rescue ArgumentError
      raise Qes::ClientError.new(code, 'Invalid base64 payload')
    end

    # Limit velikosti certu/řetězu (DoS amplifikace, SPEC § 5.2): bez limitu
    # by jeden request vyvolal N CRL fetchů a N certů v DB.
    def decode_certificate(value)
      der = decode(value, :invalid_certificate)

      if der.bytesize > MAX_CERTIFICATE_BYTES
        raise Qes::ClientError.new(:invalid_certificate, 'Certificate is too large')
      end

      der
    end
  end
end
