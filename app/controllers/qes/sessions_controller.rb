# frozen_string_literal: true

module Qes
  # Endpointy pro appku (SPEC § 5): autentizace jednorázovým tokenem v cestě,
  # v DB je jen sha256. Token se nikdy neloguje.
  class SessionsController < ApplicationController
    include Qes::ControllerConcern

    skip_before_action :authenticate_user!
    skip_authorization_check
    skip_before_action :maybe_redirect_to_setup
    protect_from_forgery with: :null_session

    before_action :check_rate_limit
    before_action :load_session

    def show
      return render_qes_error_with(:expired_token, :gone) if @session.expired?
      return render_qes_error_with(:used_token, :gone) if @session.terminal? && @session.state != 'completed'
      return render json: completed_payload if @session.state == 'completed'

      if @session.state == 'awaiting_app'
        Qes::SessionManager.transition!(@session, 'app_opened')
        Qes.log(@session)
      end

      render json: payload
    end

    def certificate
      return render_qes_error_with(:expired_token, :gone) if @session.expired?
      return render_qes_error_with(:used_token, :gone) if @session.terminal?

      certificate_der = decode_certificate(params[:certificate])
      chain = Array(params[:chain]).compact_blank.map { |der| decode_certificate(der) }
      if chain.size > MAX_CHAIN
        raise Qes::ClientError.new(:invalid_certificate, 'Certificate chain is too long')
      end
      key_location = params[:key_location].presence || 'phone_keystore'

      if @session.state == 'awaiting_signature'
        return render_qes_error_with(:wrong_state, :conflict) unless same_certificate?(certificate_der)

        return render json: certificate_payload
      end

      return render_qes_error_with(:wrong_state, :conflict) unless @session.state.in?(%w[awaiting_app app_opened])

      provider = provider_for(@session)
      # CRL fetch (síť) mimo DB transakci; transakce pak drží jen zápis (M20).
      crls = Qes::Ltv.fetch_crls(certificate_der, chain:)

      prepared = provider.data_to_sign(certificate_der, chain:, key_location:,
                                                        app_metadata: params[:app].presence,
                                                        crls: crls || [])

      Qes.log(@session)

      render json: {
        data_to_sign: Base64.strict_encode64(prepared[:signed_attrs_der]),
        hash_algorithm: prepared[:hash_algorithm],
        digest_algorithm_oid: prepared[:digest_algorithm_oid],
        signature_algorithm: prepared[:signature_algorithm],
        expires_at: @session.expires_at.utc.iso8601,
        certificate_info: prepared[:certificate_info]
      }
    rescue Qes::ClientError => e
      QesSession.where(id: @session.id).update_all(failure_code: e.code.to_s)
      @session.reload

      render_qes_error_with(e.code, :unprocessable_content)
    end

    def complete
      return render_qes_error_with(:expired_token, :gone) if @session.expired?
      return render_qes_error_with(:used_token, :gone) if @session.terminal? && @session.state != 'completed'

      signature = decode(params[:signature], :signature_invalid)

      if @session.state == 'completed'
        return render json: completed_payload if same_signature?(signature)

        # Opakované `POST /complete` s jinou signaturou nesmí projít (SPEC § 7.10).
        return render_qes_error_with(:wrong_state, :conflict)
      end

      return render_qes_error_with(:wrong_state, :conflict) unless @session.state == 'awaiting_signature'

      # Synchronně v requestu (lokální CRL/TSA) — appka dostane rovnou `completed`;
      # `complete!` je idempotentní (`with_lock` + stav), takže není potřeba job.
      Qes::Providers::MobileApp.new(@session).complete!(signature)
      @session.reload

      render json: completed_payload
    rescue Qes::ClientError => e
      fail_session(e)

      render_qes_error_with(e.code, :unprocessable_content)
    end

    def abort
      return render_qes_error_with(:expired_token, :gone) if @session.expired?
      return render_qes_error_with(:used_token, :gone) if @session.terminal?

      code = params[:code].presence || 'cancelled'
      new_state = code == 'user_cancelled' ? 'cancelled' : 'failed'

      QesSession.transaction do
        # `failure_code` je kód z appky (SPEC § 5.7), `state` stav automatu;
        # dřív se `network_error` zapsal jako `cancelled`.
        Qes::SessionManager.transition!(@session, new_state, failure_code: code,
                                                          failure_message: params[:message].presence)
      end

      Qes.log(@session)

      render json: { state: @session.state }
    end

    private

    def load_session
      token = params[:token].to_s

      @session = Qes::Token.find(token)

      if @session.nil?
        Qes::RateLimiter.record_failure!(request.remote_ip)

        return render_qes_error_with(:unknown_token, :not_found)
      end

      response.set_header('X-QES-Protocol', '1')
      response.set_header('Referrer-Policy', 'no-referrer')

      @session
    end

    def check_rate_limit
      Qes::RateLimiter.check!(request.remote_ip, token: params[:token])
    end

    def provider_for(session)
      Qes::Providers::MobileApp.new(session)
    end

    def same_certificate?(certificate_der)
      stored = @session.certificate_chain&.first
      return false if stored.blank?

      OpenSSL::X509::Certificate.new(certificate_der).to_der == Base64.decode64(stored)
    rescue OpenSSL::X509::CertificateError
      false
    end

    def same_signature?(signature)
      stored = @session.signature
      return false if stored.blank? || signature.blank?

      ActiveSupport::SecurityUtils.secure_compare(Digest::SHA256.hexdigest(stored),
                                                 Digest::SHA256.hexdigest(signature))
    end

    def payload
      submission = @session.submission

      {
        session_id: @session.id,
        state: @session.state,
        provider: @session.provider,
        document_name: submission.name.presence || submission.template&.name,
        signer_name: @session.submitter.name,
        hash_algorithm: @session.hash_algorithm,
        level_required: @session.level_required,
        requires_certificate: @session.state.in?(%w[awaiting_app app_opened]),
        server_url: Qes::Config[:public_base_url].presence || Docuseal.default_url_options[:host],
        expires_at: @session.expires_at&.utc&.iso8601
      }
    end

    def certificate_payload
      {
        data_to_sign: Base64.strict_encode64(@session.signed_attrs_der),
        hash_algorithm: @session.hash_algorithm,
        digest_algorithm_oid: Qes::CmsBuilder::DIGEST_ALGORITHM_OIDS.fetch(@session.hash_algorithm),
        signature_algorithm: @session.signature_algorithm,
        expires_at: @session.expires_at&.utc&.iso8601,
        certificate_info: @session.certificate_info
      }
    end

    def completed_payload
      {
        state: @session.state,
        session_id: @session.id,
        level: @session.level,
        document_digest: @session.document_digest,
        signed_pdf_sha256: @session.signed_pdf_sha256,
        final_pdf_sha256: @session.final_pdf_sha256,
        seal_state: @session.seal_state,
        validation: @session.validation_report,
        completed_at: @session.completed_at&.utc&.iso8601
      }
    end

    def fail_session(error)
      QesSession.where(id: @session.id).where.not(state: 'completed')
                .update_all(failure_code: error.code.to_s, failure_message: error.message,
                            failed_at: Time.current, state: 'failed')
      @session.reload
      Qes.log(@session)
    end

  end
end
