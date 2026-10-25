# frozen_string_literal: true

module Qes
  # RFC 3161 timestamp token (DocTS, SPEC § 7.6). `OpenSSL::PKCS7#data` je
  # u některých TSA (DigiCert) nil — TSTInfo je v `signedData.encapContentInfo.eContent`
  # jako `[0] EXPLICIT OCTET STRING`. Bez této cesty by se platný DocTS jevil
  # jako neplatný (K1) a `QES_TSA_REQUIRED` by nic neověřilo (K2).
  module TimestampToken
    TST_INFO_OID = '1.2.840.113549.1.9.16.1.4'
    SIGNATURE_TIMESTAMP_OID = '1.2.840.113549.1.9.16.2.14'
    CLOCK_SKEW = 300

    module_function

    # PKCS7#verify používá účel S/MIME. Řetěz TSA se proto ověřuje zvlášť
    # s TIMESTAMP_SIGN; NOVERIFY přeskočí jen tuto duplicitní S/MIME kontrolu.
    # Ověří podpis tokenu a jeho imprint proti `data` (signed data podpisu).
    def verify(pkcs7, data, trust_roots: Qes.tsa_trust_roots, at: Time.current)
      return false unless intact?(pkcs7, data)

      token_info = OpenSSL::Timestamp::TokenInfo.new(tst_info_der(pkcs7))

      return false if token_info.gen_time > at + CLOCK_SKEW
      trusted_signer?(pkcs7, token_info, trust_roots)
    rescue OpenSSL::Timestamp::TimestampError, OpenSSL::ASN1::ASN1Error, ArgumentError, TypeError
      false
    end

    # Starší revize při dokončení vyžadují podpis a imprint, nikoli dnešní trust TSA.
    def intact?(pkcs7, data)
      return false unless pkcs7.verify(pkcs7.certificates, OpenSSL::X509::Store.new, nil,
                                     OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::BINARY)

      token_info = OpenSSL::Timestamp::TokenInfo.new(tst_info_der(pkcs7))

      token_info.message_imprint == OpenSSL::Digest.digest(token_info.algorithm, data)
    rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::Timestamp::TimestampError,
           OpenSSL::ASN1::ASN1Error, OpenSSL::X509::CertificateError, ArgumentError, TypeError
      false
    end

    def verified_time(pkcs7, data, at: Time.current)
      return unless verify(pkcs7, data, at:)

      OpenSSL::Timestamp::TokenInfo.new(tst_info_der(pkcs7)).gen_time
    end

    # Imprint podpisového razítka kryje hodnotu signatury, nikoli PDF digest.
    def signature_time(pkcs7, at: Time.current)
      signed_data = OpenSSL::ASN1.decode(pkcs7.to_der).value[1].value.first
      signer_info = signed_data.value.last.value.first
      signature = signer_info.value.find { |node| node.is_a?(OpenSSL::ASN1::OctetString) }
      unsigned_attrs = signer_info.value.find { |node| node.tag_class == :CONTEXT_SPECIFIC && node.tag == 1 }
      return unless signature && unsigned_attrs

      unsigned_attrs.value.filter_map do |attribute|
        next unless attribute.value.first.oid == SIGNATURE_TIMESTAMP_OID

        attribute.value.last.value.filter_map do |token|
          verified_time(OpenSSL::PKCS7.new(token.to_der), signature.value, at:)
        end.min
      end.min
    rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error, NoMethodError, TypeError
      nil
    end

    def trusted_signer?(pkcs7, token_info, trust_roots)
      signer = VerifyPdfSignature.signer_certificate(pkcs7)
      return false if signer.nil? || trust_roots.empty?

      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_TIMESTAMP_SIGN
      store.time = token_info.gen_time
      trust_roots.each { |cert| store.add_cert(cert) }
      chain = (pkcs7.certificates || []).reject { |cert| cert.to_der == signer.to_der }

      store.verify(signer, chain)
    rescue OpenSSL::X509::StoreError
      false
    end

    def tst_info_der(pkcs7)
      content_info = OpenSSL::ASN1.decode(pkcs7.to_der)
      signed_data = content_info.value[1]&.value&.first
      encapsulated = signed_data&.value&.dig(2)

      return unless encapsulated&.value&.first&.oid == TST_INFO_OID

      encapsulated.value[1]&.value&.first&.value
    end
  end
end
