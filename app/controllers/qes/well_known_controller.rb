# frozen_string_literal: true

module Qes
  # `.well-known` soubory pro App Links / Universal Links (SPEC § 6.6).
  # AASA nemá příponu, takže statika by ho poslala jako application/octet-stream;
  # obě odpovědi proto servíruje controller s Content-Type: application/json.
  class WellKnownController < ApplicationController
    skip_before_action :authenticate_user!
    skip_authorization_check
    # Na čerstvé instalaci (žádný User) by `maybe_redirect_to_setup` vrátil
    # 302 na /setup a Android App Links verifikace by selhala (SPEC § 6.6).
    skip_before_action :maybe_redirect_to_setup

    def apple_app_site_association
      team_id = Qes::Config[:ios_team_id].presence || 'TEAMID'

      render json: {
        applinks: {
          details: [
            { appID: "#{team_id}.cz.dokulachtan.signer", paths: ['/qes/sign', '/qes/app'] }
          ]
        }
      }
    end

    def assetlinks
      fingerprint = Qes::Config[:android_cert_sha256].to_s

      render json: [
        {
          relation: ['delegate_permission/common.handle_all_urls'],
          target: {
            namespace: 'android_app',
            package_name: 'cz.dokulachtan.signer',
            sha256_cert_fingerprints: [fingerprint]
          }
        }
      ]
    end
  end
end
