# frozen_string_literal: true

module Qes
  # Validace výsledného PDF (SPEC § 7.5): kryptografická platnost podpisu,
  # důvěryhodnost vůči trust rootům, pokrytí celého dokumentu a úroveň.
  module Validator
    module_function

    def call(pdf_bytes, trust_roots: [], trusted_certs: trust_roots, at: Time.current)
      io = StringIO.new(pdf_bytes)
      signatures = signature_dicts(pdf_bytes)
      results = signatures.map { |signature| verify_one(signature, io, trust_roots, trusted_certs:) }
      trusted_ranges = signatures.zip(results).filter_map do |signature, result|
        signature[:ByteRange].value if accepted_signature?(result)
      end
      pdfium = pdfium_report(pdf_bytes, trusted_certs, trusted_ranges:)
      qes_results = results.select { |result| result[:qes] }
      last = results.last
      level = qes_results.last ? qes_results.last[:level] : 'none'

      {
        ok: results.present? && results.all? { |r| r[:intact] } &&
            results.all? { |r| accepted_signature?(r) } && last[:coverage] == 'full',
        intact: results.present? && results.all? { |result| result[:intact] },
        trusted: qes_results.present? && qes_results.all? { |result| result[:trusted] },
        coverage: last ? last[:coverage] : 'none',
        level:,
        modified: pdfium.any? { |signature| signature[:modified] },
        signatures: results,
        pdfium:,
        trusted_roots: trust_roots.map { |cert| cert.subject.to_s },
        validated_at: at.utc.iso8601
      }
    end

    def signature_dicts(pdf_bytes)
      doc = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))

      # Všechny signatury v aktuální revizi (řetězení: N podpisů appky + N pečetí).
      doc.signatures.to_a
    end

    def verify_one(signature, io, trust_roots, trusted_certs: [])
      byte_range = signature[:ByteRange]&.value&.map(&:to_i)
      contents = signature[:Contents].to_s
      sub_filter = signature[:SubFilter].to_s

      result = { sub_filter:, kind: kind_for(sub_filter), qes: sub_filter == 'ETSI.CAdES.detached',
                 signing_time: nil, common_name: nil, subject: nil, issuer: nil, serial: nil,
                 not_before: nil, not_after: nil, chain: [], level: 'none',
                 intact: false, trusted: false, coverage: 'none' }

      return result if byte_range.blank? || contents.blank?

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
      # Trust roots QES se vztahují jen na podpisy appky (CAdES); pečeť
      # DocuSealu (adbe.pkcs7.detached) se ověřuje vlastním certem účtu.
      # Ze řetězu se musí vynechat cert podepisujícího, jinak by se
      # self-signed certifikát stal sám sobě trust rootem.
      chain = pkcs7.certificates&.reject { |cert| cert.to_der == signer_cert&.to_der } || []
      result[:trusted] = result[:intact] && result[:qes] &&
                         trusted_chain?(signer_cert, chain, trust_roots)
      if result[:kind] == 'seal'
        result[:trusted] = result[:intact] && VerifyPdfSignature.trusted_certificate?(pkcs7, trusted_certs)
      end
      result[:coverage] = coverage(io.string, signature)

      result
    rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error
      result
    end

    def accepted_signature?(result)
      result[:intact] && (result[:trusted] || result[:kind] == 'timestamp')
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
      Qes::TimestampToken.verify(pkcs7, data)
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
    def trusted_chain?(certificate, chain, trust_roots)
      return false if certificate.nil? || trust_roots.blank?

      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_SMIME_SIGN
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

    # Podpis pokrývá celý soubor, pokud ByteRange sahá od začátku do konce
    # dokumentu (mezera je jen `/Contents`).
    def coverage(pdf_bytes, signature)
      byte_range = signature[:ByteRange]&.value&.map(&:to_i)
      return 'none' if byte_range.blank? || byte_range.size != 4
      return 'none' if byte_range.any?(&:negative?) || !byte_range[0].zero?

      contents_size = signature[:Contents].to_s.bytesize
      full = byte_range[2] == byte_range[1] + (contents_size * 2) + 2 &&
             byte_range[2] + byte_range[3] == pdf_bytes.bytesize

      full ? 'full' : 'partial'
    end

    def pdfium_report(pdf_bytes, trusted_certs, trusted_ranges:)
      VerifyPdfSignature.call(StringIO.new(pdf_bytes), trusted_certs, trusted_ranges:).map do |signature|
        {
          common_name: signature.common_name,
          signing_time: signature.signing_time&.utc&.iso8601,
          type: signature.type,
          verified: signature.verified,
          trusted: signature.trusted,
          modified: signature.modified,
          messages: signature.messages.map { |m| { status: m.status, text: m.text } }
        }
      end
    rescue StandardError => e
      Rails.logger.warn("[qes] pdfium validation failed: #{e.class}")

      []
    end
  end
end
