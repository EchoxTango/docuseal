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

    def apply(pdf_bytes, crls: [], certs: [], ocsps: [], signature_contents: nil)
      crls = Array(crls)
      certs = Array(certs)
      ocsps = Array(ocsps)
      return pdf_bytes if crls.blank? && certs.blank? && ocsps.blank?

      pdf = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))
      # Nový slovník zachová důkazy i VRI předchozích podepisujících.
      dss = pdf.add(pdf.catalog[:DSS]&.value&.dup || { Type: :DSS })
      refs = { CRL: [:CRLs, crls], Cert: [:Certs, certs], OCSP: [:OCSPs, ocsps] }.transform_values do |key, ders|
        existing = stream_refs(pdf, dss[key])
        by_content = existing.index_by(&:stream)
        incoming = ders.uniq.map do |der|
          by_content[der] ||= pdf.add({ Type: :EmbeddedFile }, stream: der)
        end
        dss[key] = by_content.values if by_content.any?
        incoming
      end

      if signature_contents.present?
        key = Digest::SHA1.hexdigest(signature_contents).upcase.to_sym
        entries = pdf.add(dss[:VRI]&.value&.dup || {})
        vri = pdf.add(entries[key]&.value&.dup || { Type: :VRI })
        vri[:TU] = Time.now.utc.strftime('D:%Y%m%d%H%M%SZ')
        refs.each do |type, incoming|
          merged = (stream_refs(pdf, vri[type]) + incoming).uniq(&:stream)
          vri[type] = merged if merged.any?
        end
        entries[key] = vri
        dss[:VRI] = entries
      end

      pdf.catalog[:DSS] = dss

      io = StringIO.new
      pdf.write(io, incremental: true, validate: false)
      io.string
    end

    def stream_refs(pdf, array)
      array ? array.map { |ref| pdf.deref(ref) }.uniq(&:stream) : []
    end
  end
end
