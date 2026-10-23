# frozen_string_literal: true

module Qes
  # RFC 3161 timestamp token (DocTS, SPEC § 7.6). `OpenSSL::PKCS7#data` je
  # u některých TSA (DigiCert) nil — TSTInfo je v `signedData.encapContentInfo.eContent`
  # jako `[0] EXPLICIT OCTET STRING`. Bez této cesty by se platný DocTS jevil
  # jako neplatný (K1) a `QES_TSA_REQUIRED` by nic neověřilo (K2).
  module TimestampToken
    TST_INFO_OID = '1.2.840.113549.1.9.16.1.4'

    module_function

    # Ověří podpis tokenu a jeho imprint proti `data` (signed data podpisu).
    def verify(pkcs7, data)
      return false unless pkcs7.verify(pkcs7.certificates, OpenSSL::X509::Store.new, nil,
                                     OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::BINARY)

      token_info = OpenSSL::Timestamp::TokenInfo.new(tst_info_der(pkcs7))

      token_info.message_imprint == OpenSSL::Digest.digest(token_info.algorithm, data)
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
