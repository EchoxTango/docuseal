# frozen_string_literal: true

module Qes
  # Sestavení CMS: placeholder → podepsané atributy → finální CMS s raw signaturou
  # (SPEC § 7.2 a § 7.3). Server nepočítá hash znovu — signatura je nad
  # identickými `signed_attrs_der`, což se ověřuje byte-identical kontrolou.
  module CmsBuilder
    DIGEST_ALGORITHM_OIDS = {
      'sha256' => '2.16.840.1.101.3.4.2.1',
      'sha384' => '2.16.840.1.101.3.4.2.2',
      'sha512' => '2.16.840.1.101.3.4.2.3'
    }.freeze

    SIGNING_TIME_OID = '1.2.840.113549.1.9.5'

    module_function

    # Vytvoří CMS s placeholder signaturou a vrátí podepsané atributy.
    def prepare(data:, certificate:, chain: [], signing_time: Time.current, digest_algorithm: 'sha256',
                 signature_size: Qes::Config[:signature_size])
      creator = build_creator(certificate:, chain:, signing_time:, digest_algorithm:, signature_size:)
      creator.create(data, type: :pades)

      {
        signed_attrs_der: creator.signed_attrs_der,
        digest_algorithm_oid: DIGEST_ALGORITHM_OIDS.fetch(digest_algorithm)
      }
    end

    # Sestaví finální CMS s raw signaturou; ověří byte-identical podepsané atributy.
    def complete(data:, signed_attrs_der:, signature:, certificate:, chain: [], tsa_url: nil,
                 signing_time: nil, digest_algorithm: 'sha256')
      signing_time ||= signing_time_from(signed_attrs_der)

      creator = build_creator(certificate:, chain:, signing_time:, digest_algorithm:,
                              signature_size: Qes::Config[:signature_size])
      creator.external_signature = signature
      creator.timestamp_handler = Submissions::TimestampHandler.new(tsa_url:) if tsa_url.present?

      cms_der = creator.create(data, type: :pades).to_der

      if creator.signed_attrs_der != signed_attrs_der
        raise ClientError.new(:signing_context_mismatch, 'Signed attributes differ from the prepared ones')
      end

      cms_der
    end

    # Horní odhad velikosti finálního CMS pro rezervu `/Contents` (SPEC § 7.1).
    # Placeholder signatury má velikost `QES_SIGNATURE_SIZE` (skutečná signatura
    # RSA/ECDSA je kratší), takže se finální CMS do odhadu vejde; TSA token
    # a případný růst CRL mezi fázemi kryje `QES_SIGNATURE_SIZE_MARGIN`.
    def estimate_size(certificate:, chain: [], signing_time: Time.current,
                      digest_algorithm: 'sha256')
      size = Qes::Config[:signature_size].to_i
      creator = build_creator(certificate:, chain:, signing_time:, digest_algorithm:,
                              signature_size: size)
      creator.external_signature = ("\x00".b * size)

      creator.create(OpenSSL::Digest.digest(digest_algorithm, ''), type: :pades).to_der.bytesize
    end

    # Přečte `signingTime` z DER `SET` podepsaných atributů (aby byl v obou fázích identický).
    def signing_time_from(signed_attrs_der)
      attrs = OpenSSL::ASN1.decode(signed_attrs_der)
      attribute = Array(attrs.value).find do |attr|
        attr.is_a?(OpenSSL::ASN1::Sequence) && attr.value.first&.oid == SIGNING_TIME_OID
      end
      value = attribute&.value&.last&.value&.first&.value

      value.is_a?(Time) ? value.utc : value.to_time.utc
    end

    def build_creator(certificate:, chain:, signing_time:, digest_algorithm:, signature_size:)
      creator = Qes::PlaceholderSignedDataCreator.new
      creator.certificate = certificate
      creator.certificates = chain
      creator.signing_time = signing_time.utc
      creator.digest_algorithm = digest_algorithm
      creator.signature_size = signature_size
      creator
    end

    # Ověří raw signaturu proti certifikátu a podepsaným atributům (SPEC § 5.3).
    def verify_signature!(certificate, signature, signed_attrs_der, digest_algorithm)
      return if certificate.nil? || signature.blank? || signed_attrs_der.blank?

      valid = certificate.public_key.verify(OpenSSL::Digest.new(digest_algorithm), signature, signed_attrs_der)

      raise ClientError.new(:signature_invalid, 'Signature does not match the certificate') unless valid
    rescue OpenSSL::PKey::PKeyError, OpenSSL::Digest::DigestError => e
      raise ClientError.new(:signature_invalid, e.message)
    end
  end
end
