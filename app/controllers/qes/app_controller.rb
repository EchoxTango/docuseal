# frozen_string_literal: true

module Qes
  # Web fallback stránka `/qes/app` a `/qes/sign` (SPEC § 6.4): QR kód,
  # tlačítko pro otevření appky a odkaz na stažení. Bez citlivých dat.
  class AppController < ApplicationController
    skip_before_action :authenticate_user!
    skip_authorization_check
    layout 'form'

    def show
      @token = params[:token].to_s
      @session = Qes::Token.find(@token)
      @universal_link = Qes::Link.call(request, '/qes/sign', @token)
      @custom_scheme_link = "#{Qes::Config[:deep_link_base]}?token=#{CGI.escape(@token)}"
      @fallback_url = Qes::Link.call(request, '/qes/app', @token)
      @document_name = @session&.submission&.name.presence || @session&.submission&.template&.name
      @signer_name = @session&.submitter&.name
      @expires_at = @session&.expires_at
      @qr_svg = RQRCode::QRCode.new(@universal_link, level: :m).as_svg(viewbox: true)
    end
  end
end
