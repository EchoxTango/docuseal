# frozen_string_literal: true

module Qes
  # Kontrola a normalizace nahraného PDF pro přímý podpis (docs/15 § 5.1).
  # Jediné místo, kde je potřeba vlastní logika nad rámec DocuSeal: DocuSeal
  # umí PDF zobrazit i podepsat, ale (a) nepozná, že je už podepsané (výsledek
  # se staví znovu ze stránek a původní podpis by zmizel) a (b) kreslí pole
  # v needitovaném prostoru stránky, zatímco náhled se renderuje po otočení.
  module PdfSource
    module_function

    # Ověří, že PDF není šifrované; podepsaná PDF jsou povolená jen
    # pro ověření (`allow_signed: true`), pro přímý podpis se odmítají.
    def validate!(data, allow_signed: false)
      pdf = HexaPDF::Document.new(io: StringIO.new(data))

      raise ClientError.new(:encrypted_pdf, 'Encrypted PDF is not supported') if pdf.encrypted?
      if !allow_signed && pdf.signatures.to_a.any?
        raise ClientError.new(:already_signed, 'Signed PDF is not supported')
      end
    rescue HexaPDF::EncryptionError
      raise ClientError.new(:encrypted_pdf, 'Encrypted PDF is not supported')
    rescue HexaPDF::Error
      raise ClientError.new(:invalid_pdf, 'Invalid PDF file')
    end

    # `/Rotate` se přepíše do obsahu stránky (`/Rotate 0`), aby souřadnice
    # klepnutí z náhledu seděly i na otočených stránkách. Bez rotace vrací `nil`.
    def normalize_rotation(data)
      pdf = HexaPDF::Document.new(io: StringIO.new(data))
      changed = false

      pdf.pages.each do |page|
        rotation = page[:Rotate].to_i % 360
        next if rotation.zero?

        # Děděné hodnoty se musí přenést na stránku, aby je `flatten` přepsal.
        page.value[:Rotate] = rotation
        page[:MediaBox] = page[:MediaBox] if page.value[:MediaBox].nil?
        page[:CropBox] = page[:CropBox] if page.value[:CropBox].nil? && page[:CropBox]
        page.rotate(0, flatten: true)
        changed = true
      end

      return unless changed

      io = StringIO.new
      pdf.write(io)

      io.string
    rescue HexaPDF::Error
      nil
    end

    # Rozměry stránek v bodech (viditelná orientace) — appka z nich počítá
    # normalizovanou velikost pečeti a obrys.
    def page_sizes(data)
      doc = Pdfium::Document.open_io(StringIO.new(data))

      (0...doc.page_count).map do |index|
        page = doc.get_page(index)
        size = { width: page.width, height: page.height }
        page.close

        size
      end
    rescue Pdfium::PdfiumError
      raise ClientError.new(:invalid_pdf, 'Invalid PDF file')
    ensure
      doc&.close
    end
  end
end
