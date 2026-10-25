# frozen_string_literal: true

module Qes
  module Providers
    # Testovací provider: stejný protokol jako MobileApp, ale raw signaturu vytvoří
    # server z lokálního PKCS#12 (fixtures) — celý řetěz jde spustit bez appky.
    class Mock < MobileApp
      def initialize(session, pkcs_path: nil, password: nil)
        super(session)

        if pkcs_path.present?
          @pkcs = OpenSSL::PKCS12.new(File.binread(pkcs_path), password.to_s)
        end
      end

      # Provede celý obřad synchronně: přechody stavů jako reálný tok +
      # kryptografie z MobileApp. Vrací [pdf_bytes, validation_report].
      def sign!(submitter, field, key_location: 'phone_keystore', app_metadata: nil)
        advance_to_app_opened!

        prepared = data_to_sign(pkcs.certificate.to_der, chain: pkcs.ca_certs || [],
                                key_location:, app_metadata:,
                                crls: Qes::Ltv.fetch_crls(pkcs.certificate, chain: pkcs.ca_certs || []))

        signature = pkcs.key.sign(OpenSSL::Digest.new(session.hash_algorithm), prepared[:signed_attrs_der])

        complete!(signature)
      end

      def advance_to_app_opened!
        Qes::SessionManager.transition!(session, 'prepared') if session.state == 'created'
        Qes::SessionManager.transition!(session, 'awaiting_app') if session.state == 'prepared'
        Qes::SessionManager.transition!(session, 'app_opened') if session.state == 'awaiting_app'
      end

      def pkcs
        @pkcs or raise ClientError.new(:invalid_certificate, 'Mock provider has no PKCS#12')
      end
    end
  end
end
