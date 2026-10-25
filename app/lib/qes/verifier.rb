# frozen_string_literal: true

module Qes
  # Ověření PDF pro appku (docs/16): vrací strukturovaný report nad
  # `Qes::Validator` (QES trust roots) a `VerifyPdfSignature` (pečeť DocuSealu,
  # unsigned změny). PDF se nikam neukládá.
  module Verifier
    module_function

    def call(pdf_bytes, name:, account: nil)
      report = Qes::Validator.call(
        pdf_bytes,
        trust_roots: Qes.trust_roots,
        trusted_certs: trusted_certs_for(account)
      )
      pdfium = report[:pdfium]
      signatures = report[:signatures]
      qes = signatures.select { |signature| signature[:kind] == 'qes' }
      seals = pdfium.select { |signature| signature[:type] == 'adbe.pkcs7.detached' }
      modified = pdfium.any? { |signature| signature[:modified] }

      {
        file: { name:, size: pdf_bytes.bytesize, sha256: Digest::SHA256.hexdigest(pdf_bytes) },
        verdict: compute_verdict(signatures, qes, modified, inspection: report[:inspection]),
        inspection: report[:inspection],
        intact: report[:intact],
        trusted: report[:trusted],
        modified:,
        level: report[:level],
        coverage: report[:coverage],
        origin: origin(pdf_bytes, account),
        revocation: 'not_checked',
        seal: {
          present: seals.any?,
          trusted: seals.any? && seals.all? { |signature| signature[:verified] && signature[:trusted] },
          count: seals.size
        },
        signatures: signatures.map { |signature| signature_payload(signature) },
        trusted_roots: report[:trusted_roots],
        messages: seals.flat_map { |signature| signature[:messages] },
        validated_at: report[:validated_at]
      }
    end

    # Certy účtu pro trust pečeti; chybějící konfigurace nesmí shodit ověření.
    def trusted_certs_for(account)
      return [] if account.nil?

      Accounts.load_trusted_certs(account)
    rescue StandardError => e
      Rails.logger.warn("[qes] trusted certs unavailable: #{e.class}")

      []
    end

    def compute_verdict(signatures, qes, modified, inspection: 'complete')
      return 'invalid' unless inspection == 'complete'
      return 'unsigned' if signatures.empty?
      return 'invalid' if signatures.any? { |signature| !signature[:intact] } || modified
      return 'invalid' unless signatures.last[:coverage] == 'full'
      return 'valid_untrusted' unless signatures.all? { |signature| Qes::Validator.accepted_signature?(signature) }
      return 'valid_unqualified' if qes.empty?

      'valid'
    end

    # `origin` je informativní: potvrzuje, že přesně tento soubor vznikl
    # dokončením submissionu v tomto DocuSealu. Není to náhrada validace podpisu.
    def origin(pdf_bytes, account)
      return 'external' if account.nil?

      sha256 = Base64.urlsafe_encode64(Digest::SHA256.digest(pdf_bytes))

      if CompletedDocument.joins(:submitter)
                           .where(submitters: { account_id: account.id })
                           .exists?(sha256: sha256)
        'docuseal'
      else
        'external'
      end
    end

    def signature_payload(signature)
      {
        kind: signature[:kind],
        level: signature[:level],
        intact: signature[:intact],
        trusted: signature[:trusted],
        coverage: signature[:coverage],
        common_name: signature[:common_name],
        subject: signature[:subject],
        issuer: signature[:issuer],
        serial: signature[:serial],
        signing_time: signature[:signing_time],
        not_before: signature[:not_before],
        not_after: signature[:not_after],
        chain: signature[:chain] || []
      }
    end
  end
end
