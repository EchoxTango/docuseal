# frozen_string_literal: true

module Qes
  # Podtřída HexaPDF `SignedDataCreator`, která:
  #
  # 1. zachytí DER `SET` podepsaných atributů (`signed_attrs_der`) — to podepisuje appka,
  # 2. ve fázi `prepare` vrátí placeholder signatury (rezerva `/Contents`),
  # 3. ve fázi `complete` vrátí raw signaturu z appky,
  # 4. vynutí atribut `signingTime` (HexaPDF 1.7 ho u `type: :pades` nepřidá — SPEC § 7.2).
  class PlaceholderSignedDataCreator < HexaPDF::DigitalSignature::Signing::SignedDataCreator
    attr_reader :signed_attrs_der
    attr_accessor :signature_size, :external_signature

    private

    def digest_and_sign_data(data, &block)
      @signed_attrs_der = data

      if external_signature
        external_signature
      elsif block
        block.call(@digest_algorithm, OpenSSL::Digest.digest(@digest_algorithm, data))
      else
        ("\x00".b * signature_size.to_i)
      end
    end

    def create_signed_attrs(data, ess_cert_hash: 'sha256', signing_time: true)
      super(data, ess_cert_hash: ess_cert_hash, signing_time: true)
    end
  end
end
