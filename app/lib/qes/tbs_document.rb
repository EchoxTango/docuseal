# frozen_string_literal: true

module Qes
  # TBS PDF: základ (šablona, nebo finální PDF předchozího signera) + podpisové
  # pole s rezervou `/Contents` (SPEC § 7.1). Vzhled podpisu je neviditelný
  # (`Rect: [0, 0, 0, 0]`) — rozhodnutí uživatele, viz SPEC § 16 #8.
  #
  # Řetězení (SPEC § 4.6): další QES signer MUSÍ podepsat finální PDF
  # předchozího signera jako novou inkrementální revizi; dokument se NESMÍ
  # přestavovat (import stránek by zahodil předchozí podpisy).
  module TbsDocument
    # Handler pro TBS PDF: rezervuje `/Contents` a nechá signaturu prázdnou.
    class TbsHandler < HexaPDF::DigitalSignature::Signing::DefaultHandler
    end

    module_function

    def build(submitter, field = nil, signature_size: nil)
      base = chained_base(submitter)
      offsets = page_offsets(submitter.submission)

      if base
        # Hodnoty aktuálního signera + jeho pečeť se dokreslí do podepsaného
        # základu v nové revizi; podpisové pole se přidá inkrementálně.
        # `generate_pdfs` vrací index dokumentů (všechny hodnoty = `base`), takže
        # se používají přímo — ne kvůli side effectu mutace.
        pdfs = Submissions::GenerateResultAttachments.generate_pdfs(
          submitter, base: base, page_offsets: offsets
        )
        base = pdfs.values.first || base

        Qes::Stamp.draw(base, submitter, field, offsets)

        sign(base, signature_size)
      else
        pdf = merged_document(submitter)
        Qes::Stamp.draw(pdf, submitter, field, offsets)

        sign(pdf, signature_size)
      end
    end

    # Rezerva `/Contents` je `signature_size` (SPEC § 7.1); bez ní minimum
    # z konfigurace (TBS z fixtures a testů).
    def sign(pdf, signature_size = nil)
      io = StringIO.new
      pdf.config['signature.signing_handler'][:qes_tbs] = TbsHandler

      pdf.sign(io, handler: :qes_tbs,
                    signature_size: (signature_size || Qes::Config[:signature_min_size]).to_i,
                    signature_type: :pades,
                    external_signing: ->(_io, _byte_range) { ''.b },
                    write_options: { validate: false })
      io.string
    end

    # Finální PDF posledního dokončeného podpisu téhož podepisujícího, jinak
    # finální PDF posledního dokončeného non-viewer podepisujícího, jinak `nil`
    # (první signer staví ze šablony). Vlastní session má přednost: stejná
    # osoba může podepsat víc polí (SPEC § 4.6), druhý podpis se musí řetězit
    # na její první finální PDF, ne na PDF předchozího podepisujícího.
    def chained_base(submitter)
      own = QesSession.completed.where(submitter_id: submitter.id).order(:id).last
      return pdf_from(own) if own

      previous = submitter.submission.submitters.reject(&:viewer?)
                          .select(&:completed_at?).max_by(&:completed_at)
      session = previous && QesSession.completed.where(submitter_id: previous.id).order(:id).last

      pdf_from(session)
    end

    def pdf_from(session)
      return nil unless session&.final_document&.attached?

      HexaPDF::Document.new(io: StringIO.new(session.final_document.download))
    end

    # Globální index první stránky přílohy v základu (SPEC § 4.6): podpis pokrývá
    # spojený dokument, ale `areas[].page` je per-příloha. Metadata
    # `pdf.number_of_pages` jsou bez stahování souborů.
    def page_offsets(submission)
      offsets = {}
      offset = 0

      Submissions.filtered_conditions_schema(submission).each do |item|
        attachment = submission.schema_documents.find { |a| a.uuid == item['attachment_uuid'] }

        offsets[item['attachment_uuid']] = offset

        offset += page_count(attachment)
      end

      offsets
    end

    def page_count(attachment)
      count = attachment&.metadata&.dig('pdf', 'number_of_pages').to_i
      return count if count.positive?

      [attachment&.preview_images&.size.to_i, 1].max
    end

    # Sloučí stránky dokumentů šablony (vyplněná pole, bez `qes` hodnoty a bez pečeti).
    def merged_document(submitter)
      Submissions::GenerateCombinedAttachment.build_combined_pdf(submitter, with_audit: false)
    end

    # Vrátí data pokrytá `/ByteRange` podpisu (to, co se podepisuje).
    def signed_data(io, byte_range)
      byte_range.each_slice(2).map do |offset, length|
        io.seek(offset)
        io.read([length, io.size - offset].min)
      end.join
    end

    def byte_range(pdf_bytes)
      doc = HexaPDF::Document.new(io: StringIO.new(pdf_bytes))
      signature = doc.signatures.to_a.find { |sig| doc.revisions.current.object(sig) == sig }

      signature&.[](:ByteRange)&.value&.map(&:to_i)
    end

    def document_digest(pdf_bytes, algorithm: 'sha256')
      range = byte_range(pdf_bytes)
      return nil if range.blank?

      OpenSSL::Digest.hexdigest(algorithm, signed_data(StringIO.new(pdf_bytes), range))
    end
  end
end
