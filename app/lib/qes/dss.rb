# frozen_string_literal: true

module Qes
  # DSS slovník (PAdES-LT/LTA, ETSI EN 319 142-1): revokační data (CRL) a certy
  # do slovníku `/DSS` dokumentu, aby je validátor našel i bez sítě. Přidává se
  # jako inkrementální revize po podpisu — podpis zůstává INTACT a pokrytí
  # celého souboru drží následující DocTS (§ 7.6).
  #
  # `signature_contents` jsou raw bajty `/Contents` podpisu appky (včetně paddingu);
  # VRI klíč je SHA-1 z těchto bajtů (ETSI/Adobe), ne z hex řetězce.
  module Dss
    module_function

    def apply(pdf_bytes, crls: [], certs: [], signature_contents: nil)
      crls = Array(crls)
      certs = Array(certs)
      return pdf_bytes if crls.blank? && certs.blank?

      pdf = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))
      dss = pdf.add({ Type: :DSS })
      crl_refs = crls.map { |der| pdf.add({ Type: :EmbeddedFile }, stream: der) }
      cert_refs = certs.map { |der| pdf.add({ Type: :EmbeddedFile }, stream: der) }
      dss[:CRLs] = crl_refs if crl_refs.any?
      dss[:Certs] = cert_refs if cert_refs.any?

      if signature_contents.present?
        key = Digest::SHA1.hexdigest(signature_contents).upcase.to_sym
        vri = pdf.add({ Type: :VRI, TU: Time.now.utc.strftime('D:%Y%m%d%H%M%SZ') })
        vri[:CRL] = crl_refs if crl_refs.any?
        vri[:Cert] = cert_refs if cert_refs.any?
        dss[:VRI] = pdf.add({ key => vri })
      end

      pdf.catalog[:DSS] = dss

      io = StringIO.new
      pdf.write(io, incremental: true, validate: false)
      io.string
    end
  end
end
