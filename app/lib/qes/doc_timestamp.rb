# frozen_string_literal: true

module Qes
  # Dokumentový timestamp (PAdES-LTA, ETSI EN 319 142-1): nová inkrementální
  # revize s podpisovým polem typu `DocTimeStamp` a RFC 3161 tokenem z TSA.
  # Kryje celý dokument včetně DSS a pečeti; řetězení DocTS je evidence record.
  module DocTimestamp
    RESERVE = 20_000

    # Upstream `Submissions::TimestampHandler` už umí DocTimeStamp
    # (`finalize_objects` nastaví Type/SubFilter); chybí mu jen velikost rezervy.
    # Upstream `Submissions::TimestampHandler#sign` při chybě TSA vrátí
    # `GeneralizedTime` (falešný token) místo výjimky, takže by `QES_TSA_REQUIRED`
    # nikdy neplatilo. DocTS musí být platný RFC 3161 token nad naším digestem
    # (K2); jinak `apply` vrátí `failed` a `MobileApp#complete!` selže.
    class Handler < Submissions::TimestampHandler
      def signature_size
        RESERVE
      end

      def sign(io, byte_range)
        token = super

        verify_token!(token, digest(io, byte_range))

        token
      end

      private

      def digest(io, byte_range)
        digest = OpenSSL::Digest.new(HASH_ALGORITHM)

        byte_range.each_slice(2) do |offset, length|
          io.pos = offset
          digest << io.read(length)
        end

        digest.digest
      end

      def verify_token!(token, imprint)
        pkcs7 = OpenSSL::PKCS7.new(token)
        token_info = OpenSSL::Timestamp::TokenInfo.new(Qes::TimestampToken.tst_info_der(pkcs7))

        return if token_info.message_imprint == imprint

        raise TimestampError, 'TSA token does not match the document digest'
      rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error, OpenSSL::Timestamp::TimestampError
        raise TimestampError, 'TSA returned an invalid timestamp token'
      end
    end

    module_function

    # Vrátí [pdf_bytes, state], kde state je `applied`, `failed` nebo `none`.
    def apply(pdf_bytes, tsa_url:)
      return [pdf_bytes, 'none'] if tsa_url.blank?

      pdf = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))
      pdf.config['signature.signing_handler'][:qes_dts] = Handler
      io = StringIO.new
      pdf.sign(io, handler: :qes_dts, tsa_url:, write_options: { validate: false })

      [io.string, 'applied']
    rescue StandardError => e
      Rails.logger.error("[qes] doc timestamp failed: #{e.class}: #{e.message}")

      [pdf_bytes, 'failed']
    end
  end
end
