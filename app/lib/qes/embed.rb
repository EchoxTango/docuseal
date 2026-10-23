# frozen_string_literal: true

module Qes
  # Vloží finální CMS do TBS PDF na místo rezervy `/Contents` (SPEC § 7.3).
  # Když je CMS delší než rezerva, selže s `signature_size_exceeded` (nikdy nezkracovat).
  module Embed
    module_function

    def call(tbs_pdf_bytes, cms_der)
      io = StringIO.new(tbs_pdf_bytes.dup)

      HexaPDF::DigitalSignature::Signing.embed_signature(io, cms_der)

      io.string
    rescue HexaPDF::Error => e
      if e.message.include?('reserved space')
        raise ClientError.new(:signature_size_exceeded, e.message)
      end

      raise
    end
  end
end
