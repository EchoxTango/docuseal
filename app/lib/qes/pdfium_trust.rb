# frozen_string_literal: true

module Qes
  # Trust a hranice změn pro QES PDF. Celá orchestrace je tady, aby
  # `lib/verify_pdf_signature.rb` zůstal bit-identický s upstreamem (nález 3.3)
  # a veřejné upstream endpointy nedělaly drahé HexaPDF průchody navíc
  # (nález Major 1). Upstream primitivy se jen volají.
  module PdfiumTrust
    Result = Struct.new(:common_name, :signing_time, :type, :verified, :trusted,
                        :tsa_trusted, :modified, :messages)

    module_function

    # Vrací jeden `Result` na signaturu, stejně jako `VerifyPdfSignature.call`.
    # `trusted_ranges` omezí přijaté podpisy na konkrétní revizi (QES validace).
    def report(io, trusted_certs, trusted_ranges: nil, allow_dss_changes: true)
      Pdfium.with_instance do
        Pdfium::Document.open_io(io) do |document|
          signatures = document.signatures.select do |e|
            e.byte_range.any?(&:positive?) && e.contents.present?
          end

          next [] if signatures.blank?

          verified = signatures.select { |signature| verified?(signature, io, trusted_certs) }
          trusted_timestamps = verified.select { |signature| trusted_timestamp?(signature, io) }
          timestamps = timestamps(io)
          trusted_qes = verified.select { |signature| trusted_qes_signature?(signature, timestamps:) }
          accepted = verified.select do |signature|
            accepted?(signature, trusted_certs, trusted_ranges:, trusted_timestamps:, trusted_qes:)
          end
          last_signature = accepted.reject { |signature| signature.sub_filter == 'ETSI.RFC3161' }
                                     .max_by(&:signed_end)
          timestamp_ranges = (accepted & trusted_timestamps).map(&:byte_range)
          modified = last_signature && unsigned_changes?(io, last_signature.signed_end,
                                                          allow_dss_changes:, timestamp_ranges:)

          signatures.map do |signature|
            build_result(signature, trusted_certs, trusted_qes,
                          verified: verified.include?(signature),
                          tsa_trusted: trusted_timestamps.include?(signature),
                          modified: !!modified && signature == last_signature)
          end
        end
      end
    end

    # DocTS ověřuje `Qes::TimestampToken` (DigiCert nemá `pkcs7.data`), podpis
    # appky upstream `verified_signature?`.
    def verified?(signature, io, trusted_certs)
      unless signature.sub_filter == 'ETSI.RFC3161'
        return VerifyPdfSignature.verified_signature?(signature, io, trusted_certs)
      end

      return false unless VerifyPdfSignature.covers_signed_revision?(signature, io)

      Qes::TimestampToken.intact?(
        OpenSSL::PKCS7.new(signature.contents),
        VerifyPdfSignature.signed_data(io, signature.byte_range)
      )
    rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::Timestamp::TimestampError,
           OpenSSL::ASN1::ASN1Error
      false
    end

    # DocTS i podpisové razítko smí posunout hranici změn jen když jsou
    # důvěryhodné; razítko navíc jen když leží v předané revizi.
    def accepted?(signature, trusted_certs, trusted_ranges:, trusted_timestamps:, trusted_qes:)
      if signature.sub_filter == 'ETSI.RFC3161'
        return trusted_timestamps.include?(signature) &&
               (trusted_ranges.nil? || trusted_ranges.include?(signature.byte_range))
      end

      return trusted_ranges.include?(signature.byte_range) if trusted_ranges

      trusted?(signature, trusted_certs, trusted_qes)
    end

    # QES podpis se musí ověřit řetězem (a mít podpisový keyUsage), pečeť
    # DocuSealu vlastním certem účtu. Bez toho by šel jako trusted
    # zapsat i cert s `keyEncipherment` nebo CA cert (nález K1).
    def trusted?(signature, trusted_certs, trusted_qes)
      return true if trusted_qes.include?(signature)
      return false unless signature.sub_filter == 'adbe.pkcs7.detached'

      VerifyPdfSignature.trusted_signature?(signature, trusted_certs)
    end

    # Stejná pravidla jako upstream `unsigned_changes?`, ale s QES hranicí:
    # povolený je jen DSS a neviditelné DocTS (nález K1/B9).
    def unsigned_changes?(io, signed_end, allow_dss_changes:, timestamp_ranges:)
      return signed_end < io.size unless allow_dss_changes

      io.rewind
      !Qes::RevisionChanges.allowed?(io.read, signed_end, timestamp_ranges:)
    end

    def timestamps(io)
      io.rewind
      bytes = io.read

      Qes::Validator.document_timestamps(
        Qes::Validator.signature_dicts(bytes), StringIO.new(bytes), at: Time.current
      )
    end

    def trusted_qes_signature?(signature, timestamps: [], at: Time.current)
      return false unless signature.sub_filter == 'ETSI.CAdES.detached'

      pkcs7 = OpenSSL::PKCS7.new(signature.contents)
      signer = VerifyPdfSignature.signer_certificate(pkcs7)
      return false unless signer && Qes::CertificateInfo.new(signer).signing_leaf?

      chain = (pkcs7.certificates || []).reject { |cert| cert.to_der == signer&.to_der }

      # Oba časy prošly ověřením TSA trust rootů; min je konzervativní.
      timestamp_time = timestamps.filter_map { |range, time| time if range[1] >= signature.signed_end }.min
      evidence_time = [timestamp_time, Qes::TimestampToken.signature_time(pkcs7, at:)].compact.min

      Qes::Validator.trusted_chain?(signer, chain, Qes.trust_roots, at: evidence_time || at)
    end

    def trusted_timestamp?(signature, io)
      return false unless signature.sub_filter == 'ETSI.RFC3161'

      Qes::TimestampToken.verify(OpenSSL::PKCS7.new(signature.contents),
                                  VerifyPdfSignature.signed_data(io, signature.byte_range))
    end

    def build_result(signature, trusted_certs, trusted_qes, verified:, tsa_trusted:, modified:)
      pkcs7 = OpenSSL::PKCS7.new(signature.contents)
      trusted = trusted?(signature, trusted_certs, trusted_qes)

      Result.new(VerifyPdfSignature.common_name(pkcs7),
                 VerifyPdfSignature.signing_time(pkcs7, signature),
                 signature.sub_filter, verified, trusted,
                 tsa_trusted, modified, messages(pkcs7, verified:, trusted:, modified:))
    rescue OpenSSL::PKCS7::PKCS7Error
      Result.new(nil, VerifyPdfSignature.parse_time(signature.time), signature.sub_filter,
                  false, false, false, false,
                  [VerifyPdfSignature::MessageStruct.new(I18n.t('signature_verification_failed'), :error)])
    end

    def messages(pkcs7, verified:, trusted:, modified:)
      list =
        if verified
          [VerifyPdfSignature::MessageStruct.new(I18n.t('signature_valid'), :success),
           VerifyPdfSignature::MessageStruct.new(
             I18n.t(trusted ? 'signed_with_trusted_certificate' : 'signed_with_external_certificate'),
             trusted ? :success : :error
           )]
        else
          [VerifyPdfSignature::MessageStruct.new(I18n.t('signature_verification_failed'), :error)]
        end

      if modified
        list << VerifyPdfSignature::MessageStruct.new(
          I18n.t('contains_unsigned_changes_after_the_last_signature'), :warning
        )
      end

      list << VerifyPdfSignature::MessageStruct.new(
        "Certificate chain: #{VerifyPdfSignature.certificate_chain(pkcs7).join(' -> ')}"
      )
    end
  end
end
