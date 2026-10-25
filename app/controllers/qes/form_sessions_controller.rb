# frozen_string_literal: true

module Qes
  # Endpointy pro prohlížeč v podpisovém formuláři (SPEC § 6).
  class FormSessionsController < ApplicationController
    include Qes::ControllerConcern

    skip_before_action :authenticate_user!
    skip_authorization_check
    skip_before_action :maybe_redirect_to_setup

    before_action :load_submitter
    before_action :authorize_submitter

    # Appka spouští obřad s API tokenem (docs/15 § 5.1) — bez CSRF tokenu
    # a prohlížečové session (token je kapabilita, jako podpisový odkaz).
    skip_before_action :verify_authenticity_token, if: :api_token_user

    def create
      field = find_field
      return render_qes_error_with(:unknown_field, :not_found) if field.nil?
      return render_qes_error_with(:wrong_field_type, :unprocessable_content) unless field['type'] == 'qes'

      if @submitter.completed_at? || @submitter.declined_at? || @submitter.submission.archived_at?
        return render_qes_error_with(:form_not_active, :unprocessable_content)
      end

      # Řetězení PAdES vyžaduje striktní pořadí (SPEC § 4.6); formulář se sice
      # gateuje, ale přímý POST na endpoint musí odmítnout taky.
      unless Submitters.current_submitter_order?(@submitter)
        return render_qes_error_with(:awaiting_previous_signer, :conflict)
      end

      Qes::SigningValues.validate!(@submitter)

      session = nil
      token = nil

      # Serializuje tvorbu session; jejich stav se kontroluje pod vlastním zámkem.
      @submitter.submission.with_lock do
        QesSession.active.where(submitter_id: @submitter.id).find_each do |active|
          active.with_lock do
            if active.state == 'awaiting_signature' && active.field_uuid == field['uuid']
              session = active
            elsif active.state.in?(%w[awaiting_app app_opened])
              Qes::SessionManager.transition!(active, 'cancelled')
            end
          end
        end

        next if session

        session = QesSession.create!(account: @submitter.account, submission: @submitter.submission,
                                     submitter: @submitter, field_uuid: field['uuid'],
                                     provider: 'mobile_app')

        Qes::SessionManager.transition!(session, 'prepared')

        token = Qes::Token.generate
        session.update!(token_digest: Qes::Token.digest(token),
                        expires_at: Qes::Config[:session_ttl].to_i.seconds.from_now)

        Qes::SessionManager.transition!(session, 'awaiting_app')
      end

      Qes.log(session)

      if token.nil?
        return render json: { error: 'signature_in_progress', id: session.id, session_id: session.id,
                              state: session.state, expires_at: session.expires_at&.utc&.iso8601,
                              poll_interval_ms: 2000 }, status: :conflict
      end

      link = Qes::Link.call(request, '/qes/sign', token)

      render json: {
        id: session.id,
        state: session.state,
        token:,
        universal_link: link,
        qr_svg: RQRCode::QRCode.new(link, level: :m).as_svg(viewbox: true, svg_attributes: { width: 220, height: 220 }),
        fallback_url: Qes::Link.call(request, '/qes/app', token),
        custom_scheme_link: "#{Qes::Config[:deep_link_base]}?token=#{CGI.escape(token)}",
        expires_at: session.expires_at.utc.iso8601,
        poll_interval_ms: 2000
      }, status: :created
    end

    def show
      session = @submitter.qes_sessions.find_by(id: params[:id])

      return render_qes_error_with(:unknown_session, :not_found) if session.nil?

      render json: {
        id: session.id,
        state: session.state,
        value: session.state == 'completed' ? session.value_token : nil,
        error: session.failure_code.present? ? { code: session.failure_code,
                                                message: session.failure_message } : nil,
        completed: session.state == 'completed'
      }.merge(completed_details(session))
    end

    def cancel
      session = @submitter.qes_sessions.find_by(id: params[:id])

      return render_qes_error_with(:unknown_session, :not_found) if session.nil?

      if Qes::SessionManager.active?(session.state)
        Qes::SessionManager.transition!(session, 'cancelled')
      end

      Qes.log(session)

      render json: { state: session.state }
    end

    private

    def load_submitter
      @submitter = Submitter.find_by(slug: params[:submit_form_slug])
    end

    def authorize_submitter
      return if @submitter && Submitters::AuthorizedForForm.call(@submitter, current_user || api_token_user, request)

      render_qes_error_with(:unauthorized, :not_found)
    end

    def api_token_user
      token = request.headers['X-Auth-Token'].presence

      return if token.blank?

      @api_token_user ||= User.joins(:access_token).active.find_by(access_token: { sha256: Digest::SHA256.hexdigest(token) })
    end

    def find_field
      Qes.template_field(@submitter.submission, params[:field_uuid],
                          submitter_uuid: @submitter.uuid)
    end

    # Metadata dokončeného podpisu pro přehled v podpisovém formuláři:
    # stejný HTML přehled jako v `submissions/qes_summary`.
    def completed_details(session)
      return {} unless session.state == 'completed'

      {
        seal_state: session.seal_state,
        doc_timestamp_state: session.doc_timestamp_state,
        # `renderer` má vždy HTML formát; `render_to_string` by v JSON
        # requestu hledal `icons/_circle_check.json` a spadl by na 500.
        summary_html: ApplicationController.renderer.render(partial: 'submissions/qes_summary',
                                                          locals: { session:, compact: true })
      }
    end
  end
end
