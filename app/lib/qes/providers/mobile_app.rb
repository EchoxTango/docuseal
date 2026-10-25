# frozen_string_literal: true

module Qes
  module Providers
    # Varianta B (klíč v telefonu) i A (čip eObčanky): v obou případech
    # podepisuje appka podepsané atributy CMS, server jen skládá CMS a vkládá PDF.
    class MobileApp
      attr_reader :session

      def initialize(session)
        @session = session
      end

      # TBS se staví až po přijetí certifikátu (`data_to_sign`): rezerva
      # `/Contents` musí pojmout finální CMS a její velikost závisí na CRL
      # podepisujícího (SPEC § 7.1).
      def data_to_sign(certificate_der, chain: [], key_location: nil, app_metadata: nil, crls: [])
        chain = normalize_chain(chain)
        # `CertificateInfo.parse` vrací `ClientError(:invalid_certificate)` místo
        # `OpenSSL::X509::CertificateError` (ten by v controlleru skončil 500).
        info = Qes::CertificateInfo.parse(certificate_der)
        certificate = info.certificate
        certificate_info = info.validate!(level_required: session.level_required,
                                         key_location: key_location)

        # Certifikát musí vést řetězem k trust rootu (SPEC § 5.2); jinak by šel
        # jako QES zapsat i self-signed certifikát s podvrženými QCStatements.
        Qes::Validator.verify_chain!(certificate, chain, trust_roots)

        # CRL se stahují v controlleru před přípravou TBS; tady se jen ověří.
        Qes::Ltv.check_revoked!(certificate, chain:, crls:)

        values_snapshot = nil
        tbs_pdf = nil
        session.submitter.with_lock do
          Qes::SigningValues.prepare!(session.submitter)
          session.submitter.save!
          values_snapshot = Qes::ValueValidator.non_qes_values(session.submitter.values, session.submitter)

          tbs_pdf = Qes::TbsDocument.build(
            session.submitter, session.field,
            signature_size: tbs_signature_size(certificate, chain)
          )
        end

        data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), Qes::TbsDocument.byte_range(tbs_pdf))

        prepared = Qes::CmsBuilder.prepare(
          data: data,
          certificate: certificate,
          chain: chain,
          signing_time: Time.now.utc,
          digest_algorithm: session.hash_algorithm
        )

        # Bajty musí být uložené před zveřejněním stavu awaiting_signature.
        tbs_blob = upload_document(tbs_pdf, 'qes-tbs', metadata: { qes_values: values_snapshot })

        session.with_lock do
          unless session.state.in?(%w[awaiting_app app_opened])
            raise ClientError.new(:wrong_state, 'Session is not awaiting a certificate')
          end

          session.submitter.lock!
          if Qes::ValueValidator.non_qes_values(session.submitter.values, session.submitter) != values_snapshot
            raise ClientError.new(:values_changed, 'Field values changed during document preparation')
          end

          session.tbs_document.attach(tbs_blob)
          session.update!(
            document_digest: Qes::TbsDocument.document_digest(tbs_pdf, algorithm: session.hash_algorithm),
            signed_attrs_der: prepared[:signed_attrs_der],
            signing_time: Qes::CmsBuilder.signing_time_from(prepared[:signed_attrs_der]),
            certificate_info: certificate_info,
            certificate_chain: [certificate_der, *normalize_chain(chain)].map { |der| Base64.strict_encode64(der) },
            level: certificate_info[:level],
            key_location: key_location,
            app_metadata: app_metadata,
            failure_code: nil,
            failure_message: nil
          )
          Qes::SessionManager.transition!(session, 'app_opened') if session.state == 'awaiting_app'
          Qes::SessionManager.transition!(session, 'awaiting_signature')
        end

        {
          data_to_sign: Base64.strict_encode64(prepared[:signed_attrs_der]),
          signed_attrs_der: prepared[:signed_attrs_der],
          hash_algorithm: session.hash_algorithm,
          digest_algorithm_oid: prepared[:digest_algorithm_oid],
          signature_algorithm: session.signature_algorithm,
          certificate_info: certificate_info
        }
      end

      def build_cms(signature)
        certificates = session.certificate_chain.map { |der| OpenSSL::X509::Certificate.new(Base64.decode64(der)) }
        certificate = certificates.first
        chain = certificates.drop(1)
        tbs_pdf = session.tbs_document.download
        data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), Qes::TbsDocument.byte_range(tbs_pdf))

        Qes::CmsBuilder.complete(
          data: data,
          signed_attrs_der: session.signed_attrs_der,
          signature: signature,
          certificate: certificate,
          chain: chain,
          tsa_url: Qes::Config[:tsa_url],
          digest_algorithm: session.hash_algorithm
        )
      end

      # Revokační data pro DSS (jeden fetch); CMS LTV už nepoužíváme.
      def ltv_values
        certificates = session.certificate_chain.map { |der| OpenSSL::X509::Certificate.new(Base64.decode64(der)) }
        crls = Qes::Ltv.fetch_crls(certificates.first, chain: certificates.drop(1))

        Qes::Ltv.check_revoked!(certificates.first, chain: certificates.drop(1), crls:) if crls

        crls && { crls: crls.map(&:to_der) }
      end

      def embed(cms_der)
        tbs_pdf = session.tbs_document.download

        Qes::Embed.call(tbs_pdf, cms_der)
      end

      def validate(pdf_bytes)
        # Chybějící certifikáty účtu (pečeť nenastavená) nesmí shodit dokončení.
        trusted_certs = Qes::Verifier.trusted_certs_for(session.account)
        trusted_certs += [seal_pkcs.certificate] if seal_pkcs

        current_signature_range = Qes::TbsDocument.byte_range(session.tbs_document.download)

        Qes::Validator.call(pdf_bytes, trust_roots:, trusted_certs:, current_signature_range:)
      end

      def trust_roots
        Qes.trust_roots
      end

      # Dokončení obřadu: ověří raw signaturu, sestaví CMS, vloží PAdES, validuje,
      # přidá pečeť a v jedné transakci uloží dokumenty + nastaví hodnotu pole.
      # Zámek řádku (`with_lock`) serializuje souběžná dokončení; druhé volání
      # vidí už `completed` a vrací uložený report (idempotence).
      def complete!(signature)
        return session.validation_report if session.state == 'completed'

        unless session.state == 'awaiting_signature'
          raise ClientError.new(:wrong_state, 'Session is not awaiting a signature')
        end

        if Qes::Config[:tsa_url].present? && Qes.tsa_trust_roots.empty?
          raise ClientError.new(:tsa_trust_not_configured,
                                'QES_TSA_URL requires TSA trust roots; configure QES_TSA_TRUST_ROOTS')
        end

        # Dlouhé síťové operace (CRL fetch, TSA, PDF) mimo `with_lock`; transakce
        # pak drží jen zápis stavu a dokumentů (M20).
        Qes::CmsBuilder.verify_signature!(session.certificate, signature,
                                          session.signed_attrs_der, session.hash_algorithm)

        revocation_data = ltv_values
        cms_der = build_cms(signature)
        signed_pdf = embed(cms_der)
        report = validate(signed_pdf)

        # `ok` obsahuje intact + trusted (proti trust rootům) + plné pokrytí;
        # bez trusted by se AdES/self-signed certifikát zapsal jako QES (SPEC § 4.3).
        unless report[:ok]
          raise ClientError.new(:validation_failed, 'Signature validation failed')
        end

        # DSS (PAdES-LT) až po validaci — revokační data pro offline
        # validaci; podpis zůstává INTACT. VRI klíč je SHA-1 `/Contents`
        # podpisu appky (SPEC § 7.4).
        signed_pdf = Qes::Dss.apply(
          signed_pdf,
          crls: revocation_data&.fetch(:crls, []),
          certs: certificate_chain_der,
          signature_contents: signature_contents(signed_pdf)
        )

        final_pdf, seal_state = Qes::Seal.apply(signed_pdf, session.account, submitter: session.submitter,
                                                 pkcs: seal_pkcs)
        raise ClientError.new(:seal_failed, 'Document seal failed; retry completion') if seal_state == 'failed'

        # DocTS (PAdES-LTA) až po DSS a pečeti — kryje celý dokument
        # včetně revokačních dat a pečeti; řetězení DocTS je evidence record.
        final_pdf, doc_timestamp_state = Qes::DocTimestamp.apply(final_pdf, tsa_url: Qes::Config[:tsa_url])

        if doc_timestamp_state != 'applied' && Qes::Config[:tsa_required]
          raise ClientError.new(:tsa_unavailable, 'Document timestamp failed')
        end

        # Finální PDF má podpis appky + DSS + pečeť + DocTS; pokrytí podpisu
        # appky je v něm částečné (DSS je až za ním), proto se `ok` vztahuje
        # k podpisu před DSS. Starší revize musí být neporušené; vlastní podpis,
        # nová pečeť a DocTS musí projít úplnou validací.
        final_report = validate(final_pdf)
        unless final_report[:inspection] == 'complete' && !final_report[:modified] &&
               final_report[:intact] && final_report[:trusted] &&
               final_report[:signatures].all? { |result| Qes::Validator.valid_for_scope?(result) }
          raise ClientError.new(:validation_failed, 'Signature validation failed')
        end

        report[:signer_validation] = final_report[:signatures].find do |result|
          result[:qes] && result[:verification_scope] == 'full'
        end
        if doc_timestamp_state == 'applied'
          timestamp = final_report[:signatures].last
          unless timestamp[:kind] == 'timestamp' && timestamp[:verification_scope] == 'full' &&
                 timestamp[:coverage] == 'full' && Qes::Validator.accepted_signature?(timestamp)
            raise ClientError.new(:validation_failed, 'Document timestamp validation failed')
          end

          report[:doc_timestamp] = timestamp
        end

        signed_blob = upload_document(signed_pdf, 'qes-signed')
        final_blob = upload_document(final_pdf, 'qes-final')

        session.with_lock do
          return session.validation_report if session.state == 'completed'

          unless session.state == 'awaiting_signature'
            raise ClientError.new(:wrong_state, 'Session is not awaiting a signature')
          end

          submitter = session.submitter
          submitter.lock!
          snapshot = session.tbs_document.blob.metadata['qes_values']
          if snapshot && Qes::ValueValidator.non_qes_values(submitter.values, submitter) != snapshot
            raise ClientError.new(:values_changed, 'Field values changed after document preparation')
          end

          # `signed_document` (bez pečeti) se uchovává pro audit a
          # reprodukovatelnost hashe `signed_pdf_sha256` (SPEC § 7.6 bod 3).
          session.signed_document.attach(signed_blob)
          session.final_document.attach(final_blob)
          session.update!(signature:, signed_pdf_sha256: Digest::SHA256.hexdigest(signed_pdf),
                          final_pdf_sha256: Digest::SHA256.hexdigest(final_pdf),
                          seal_state:, doc_timestamp_state:, validation_report: report,
                          failure_code: nil, failure_message: nil)
          Qes::SessionManager.transition!(session, 'signed')
          Qes::SessionManager.transition!(session, 'embedded')
          Qes::SessionManager.transition!(session, 'validated')
          Qes::SessionManager.transition!(session, 'completed')

          submitter.update!(values: submitter.values.merge(session.field_uuid => session.value_token))

          Qes.log(session)

          report
        end
      end

      private

      def upload_document(bytes, prefix, metadata: {})
        ActiveStorage::Blob.create_and_upload!(
          io: StringIO.new(bytes),
          filename: "#{prefix}-#{session.id}.pdf",
          content_type: 'application/pdf',
          metadata:
        )
      end

      def seal_pkcs
        return unless Qes::Config[:seal_pkcs_path].present?

        OpenSSL::PKCS12.new(File.binread(Qes::Config[:seal_pkcs_path]), Qes::Config[:seal_pkcs_password].to_s)
      end

      def normalize_chain(chain)
        Array(chain).map { |cert| cert.is_a?(OpenSSL::X509::Certificate) ? cert.to_der : cert }
      end

      # Rezerva `/Contents` = horní odhad CMS (bez LTV, to jde do DSS) + marže
      # pro TSA token (SPEC § 7.1); minimum je `QES_SIGNATURE_SIZE`.
      def tbs_signature_size(certificate, chain)
        minimum = Qes::Config[:signature_min_size].to_i
        estimate = Qes::CmsBuilder.estimate_size(
          certificate:, chain:, signing_time: Time.now.utc,
          digest_algorithm: session.hash_algorithm
        )

        [minimum, estimate + Qes::Config[:signature_size_margin].to_i].max
      end

      def certificate_chain_der
        session.certificate_chain.map { |der| Base64.decode64(der) }
      end

      # Raw `/Contents` (včetně paddingu) pro VRI klíč v DSS.
      def signature_contents(pdf_bytes)
        pdf = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))

        pdf.signatures.to_a.last&.[](:Contents).to_s
      end
    end
  end
end
