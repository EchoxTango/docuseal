# frozen_string_literal: true

module Qes
  # Validace výsledného PDF (SPEC § 7.5): kryptografická platnost podpisu,
  # důvěryhodnost vůči trust rootům, pokrytí celého dokumentu a úroveň.
  module Validator
    module_function

    def call(pdf_bytes, trust_roots: [], trusted_certs: trust_roots, at: Time.current,
             current_signature_range: nil)
      io = StringIO.new(pdf_bytes)
      signatures = signature_dicts(pdf_bytes)
      timestamps = document_timestamps(signatures, io, at:)
      results = signatures.map do |signature|
        byte_range = signature[:ByteRange]&.value
        signed_end = byte_range[2] + byte_range[3] if valid_byte_range?(pdf_bytes, signature)
        timestamp_time = timestamps.filter_map do |range, time|
          time if signed_end && range[1] >= signed_end
        end.min

        historical = current_signature_range && signed_end &&
                     signed_end < current_signature_range[2] + current_signature_range[3]

        verify_one(signature, io, trust_roots, trusted_certs:, at:, timestamp_time:, historical:)
      end
      trusted_ranges = signatures.zip(results).filter_map do |signature, result|
        signature[:ByteRange].value if accepted_signature?(result)
      end
      pdfium = pdfium_report(pdf_bytes, trusted_certs, trusted_ranges:,
                            allow_dss_changes: current_signature_range.present?)
      inspection = if pdfium && pdfium.size == results.size && pdfium.all? { |signature| signature[:verified] }
                     'complete'
                   else
                     'indeterminate'
                   end
      pdfium ||= []
      qes_results = results.select { |result| result[:qes] }
      current_qes = qes_results.reject { |result| result[:verification_scope] == 'integrity' }
      current_present = current_signature_range.nil? || signatures.zip(results).any? do |signature, result|
        result[:qes] && signature[:ByteRange]&.value == current_signature_range
      end
      last = results.last
      level = qes_results.last ? qes_results.last[:level] : 'none'

      {
        ok: inspection == 'complete' && !pdfium.any? { |signature| signature[:modified] } &&
            qes_results.present? && current_present && results.all? { |r| valid_for_scope?(r) } &&
            last[:coverage] == 'full',
        intact: results.present? && results.all? { |result| result[:intact] },
        trusted: current_present && current_qes.present? && current_qes.all? { |result| result[:trusted] },
        validation_scope: current_signature_range ? 'current_revision' : 'document',
        coverage: last ? last[:coverage] : 'none',
        level:,
        modified: pdfium.any? { |signature| signature[:modified] },
        signatures: results,
        pdfium:,
        inspection:,
        trusted_roots: trust_roots.map { |cert| cert.subject.to_s },
        validated_at: at.utc.iso8601
      }
    end

    def signature_dicts(pdf_bytes)
      doc = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))

      # Všechny signatury v aktuální revizi (řetězení: N podpisů appky + N pečetí).
      doc.signatures.to_a
    end

    def verify_one(signature, io, trust_roots, trusted_certs: [], at: Time.current, timestamp_time: nil,
                   historical: false)
      byte_range = signature[:ByteRange]&.value&.map(&:to_i)
      contents = signature[:Contents].to_s
      sub_filter = signature[:SubFilter].to_s

      result = { sub_filter:, kind: kind_for(sub_filter), qes: sub_filter == 'ETSI.CAdES.detached',
                 signing_time: nil, common_name: nil, subject: nil, issuer: nil, serial: nil,
                 not_before: nil, not_after: nil, chain: [], level: 'none',
                 intact: false, trusted: false, tsa_trusted: false, coverage: 'none',
                 verification_scope: historical ? 'integrity' : 'full', timestamp_time: nil,
                 validated_at_time: at.utc.iso8601, time_source: 'current' }

      return result unless valid_byte_range?(io.string, signature)

      data = Qes::TbsDocument.signed_data(io, byte_range)
      pkcs7 = OpenSSL::PKCS7.new(contents)
      signer_cert = VerifyPdfSignature.signer_certificate(pkcs7)

      result[:common_name] = common_name(signer_cert)
      result[:subject] = signer_cert&.subject&.to_s
      result[:issuer] = signer_cert&.issuer&.to_s
      result[:serial] = signer_cert ? "0x#{signer_cert.serial.to_s(16).upcase}" : nil
      result[:not_before] = signer_cert&.not_before&.utc&.iso8601
      result[:not_after] = signer_cert&.not_after&.utc&.iso8601
      result[:chain] = pkcs7.certificates&.map { |cert| cert.subject.to_s } || []
      result[:signing_time] = signing_time(pkcs7)
      result[:level] = signer_cert ? Qes::CertificateInfo.new(signer_cert).level : 'none'
      result[:intact] = verify_cms(pkcs7, data, trust_roots, sub_filter)
      evidence_time = if result[:kind] == 'timestamp'
                        Qes::TimestampToken.verified_time(pkcs7, data, at:)
                      else
                        [timestamp_time, Qes::TimestampToken.signature_time(pkcs7, at:)].compact.min
                      end
      validation_time = evidence_time || at
      result[:timestamp_time] = evidence_time&.utc&.iso8601 if result[:kind] == 'timestamp'
      result[:validated_at_time] = validation_time.utc.iso8601
      result[:time_source] = evidence_time ? 'timestamp' : 'current'
      result[:tsa_trusted] = evidence_time.present?
      # Trust roots QES se vztahují jen na podpisy appky (CAdES); pečeť
      # DocuSealu (adbe.pkcs7.detached) se ověřuje vlastním certem účtu.
      # Ze řetězu se musí vynechat cert podepisujícího, jinak by se
      # self-signed certifikát stal sám sobě trust rootem.
      chain = pkcs7.certificates&.reject { |cert| cert.to_der == signer_cert&.to_der } || []
      result[:trusted] = result[:intact] && result[:qes] &&
                         trusted_chain?(signer_cert, chain, trust_roots, at: validation_time)
      if result[:kind] == 'seal'
        result[:trusted] = result[:intact] && VerifyPdfSignature.trusted_certificate?(pkcs7, trusted_certs)
      end
      result[:coverage] = coverage(io.string, signature)

      result
    rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error
      result
    end

    # DocTS musí krýt celou starší revizi včetně hodnoty podpisu.
    def document_timestamps(signatures, io, at:)
      signatures.filter_map do |signature|
        next unless signature[:SubFilter].to_s == 'ETSI.RFC3161'
        next unless valid_byte_range?(io.string, signature)

        range = signature[:ByteRange].value
        token = OpenSSL::PKCS7.new(signature[:Contents].to_s)
        time = Qes::TimestampToken.verified_time(token, Qes::TbsDocument.signed_data(io, range), at:)

        [range, time] if time
      rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error
        nil
      end
    end

    def accepted_signature?(result)
      return result[:intact] && result[:tsa_trusted] if result[:kind] == 'timestamp'

      if result[:verification_scope] == 'integrity'
        return result[:intact] && result[:kind].in?(%w[qes seal])
      end

      result[:intact] && result[:trusted]
    end

    # B4-8: starší DocTS při dokončení vyžaduje pouze integritu. Tato výjimka
    # mu nedává právo posunout hranici změn ani poskytnout historický čas.
    def valid_for_scope?(result)
      if result[:verification_scope] == 'integrity' && result[:kind] == 'timestamp'
        return result[:intact]
      end

      accepted_signature?(result)
    end

    # `SignerInfo#signed_time` vyhodí `PKCS7Error` s prázdnou zprávou, když
    # token nemá atribut `signingTime` (RFC 3161 ho nevyžaduje, DocTS ho nemá).
    def signing_time(pkcs7)
      pkcs7.signers.first&.signed_time&.utc&.iso8601
    rescue StandardError
      nil
    end

    def kind_for(sub_filter)
      case sub_filter
      when 'ETSI.CAdES.detached' then 'qes'
      when 'adbe.pkcs7.detached' then 'seal'
      when 'ETSI.RFC3161' then 'timestamp'
      else 'other'
      end
    end

    def common_name(certificate)
      return if certificate.nil?

      certificate.subject.to_a.assoc('CN')&.dig(1)
    end

    # Kryptografie je v `VerifyPdfSignature` (jeden zdroj pravdy pro pečeť i
    # QES podpisy); tady se jen rozlišuje DocTS a přidává trust vůči QES rootům.
    def verify_cms(pkcs7, data, trust_roots, sub_filter)
      if sub_filter == 'ETSI.RFC3161'
        verify_timestamp(pkcs7, data)
      else
        VerifyPdfSignature.verify_contents(pkcs7, data, trust_roots)
      end
    end

    def verify_timestamp(pkcs7, data)
      Qes::TimestampToken.intact?(pkcs7, data)
    rescue OpenSSL::Timestamp::TimestampError, OpenSSL::ASN1::ASN1Error
      false
    end

    # Ověří, že certifikát podepisujícího vede řetězem k některému z trust rootů
    # (SPEC § 5.2 a § 7.5). Bez toho by šel jako QES zapsat i self-signed certifikát.
    def verify_chain!(certificate, chain, trust_roots)
      if trust_roots.blank?
        raise ClientError.new(:not_trusted, 'No QES trust roots configured')
      end

      return if trusted_chain?(certificate, chain, trust_roots)

      raise ClientError.new(:not_trusted, 'Certificate chain does not lead to a trusted root')
    end

    # Důvěryhodnost vůči trust rootům. Do store se musí přidat i intermediate
    # certifikáty z CMS — bez nich OpenSSL řetěz nepostaví a reálné kvalifikované
    # certifikáty (I.CA/PostSignum) by vycházely jako nedůvěryhodné.
    def trusted_chain?(certificate, chain, trust_roots, at: Time.current)
      return false if certificate.nil? || trust_roots.blank?

      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.time = at
      trust_roots.each { |cert| store.add_cert(cert) }

      # `chain` jsou untrusted intermediate certifikáty z CMS; do store se
      # nesmí přidat jako trusted, jinak by se root z CMS stal trust rootem.
      store.verify(certificate, untrusted_chain(chain))
    rescue OpenSSL::X509::StoreError, OpenSSL::X509::CertificateError
      false
    end

    def untrusted_chain(chain)
      Array(chain).filter_map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      rescue OpenSSL::X509::CertificateError
        nil
      end
    end

    def valid_byte_range?(pdf_bytes, signature)
      byte_range = signature[:ByteRange]&.value
      return false unless byte_range&.size == 4 && byte_range.all? { |value| value.is_a?(Integer) && value >= 0 }
      return false unless byte_range[0].zero? && signature[:Contents].to_s.present?

      byte_range[2] == byte_range[1] + (signature[:Contents].to_s.bytesize * 2) + 2 &&
        byte_range[2] + byte_range[3] <= pdf_bytes.bytesize
    end

    # Poslední podpis musí krýt celý soubor; starší mohou krýt vlastní revizi.
    def coverage(pdf_bytes, signature)
      return 'none' unless valid_byte_range?(pdf_bytes, signature)

      byte_range = signature[:ByteRange].value
      byte_range[2] + byte_range[3] == pdf_bytes.bytesize ? 'full' : 'partial'
    end

    def pdfium_report(pdf_bytes, trusted_certs, trusted_ranges:, allow_dss_changes: false)
      VerifyPdfSignature.call(StringIO.new(pdf_bytes), trusted_certs,
                              trusted_ranges:, allow_dss_changes:).map do |signature|
        {
          common_name: signature.common_name,
          signing_time: signature.signing_time&.utc&.iso8601,
          type: signature.type,
          verified: signature.verified,
          trusted: signature.trusted,
          tsa_trusted: signature.tsa_trusted,
          modified: signature.modified,
          messages: signature.messages.map { |m| { status: m.status, text: m.text } }
        }
      end
    rescue StandardError => e
      Rails.logger.warn("[qes] pdfium validation failed: #{e.class}")

      nil
    end
  end
end
