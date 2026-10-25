# frozen_string_literal: true

module VerifyPdfSignature
  COMMON_NAME = 'CN'
  TIME_FORMAT = '%Y%m%d%H%M%S%z'

  SignatureStruct = Struct.new(:messages, :reason, :signing_time, :common_name, :type,
                              :verified, :trusted, :modified, :tsa_trusted)
  MessageStruct = Struct.new(:text, :status)

  module_function

  def call(io, trusted_certs, trusted_ranges: nil, allow_dss_changes: true)
    Pdfium.with_instance do
      Pdfium::Document.open_io(io) do |document|
        signatures = document.signatures.select { |e| e.byte_range.any?(&:positive?) && e.contents.present? }

        next [] if signatures.blank?

        verified_signatures = signatures.select do |signature|
          verified_signature?(signature, io, trusted_certs)
        end
        trusted_signatures = verified_signatures.select { |e| trusted_signature?(e, trusted_certs) }
        trusted_timestamps = verified_signatures.select { |signature| trusted_timestamp?(signature, io) }
        io.rewind
        timestamp_io = StringIO.new(io.read)
        timestamps = Qes::Validator.document_timestamps(
          Qes::Validator.signature_dicts(timestamp_io.string), timestamp_io, at: Time.current
        )
        trusted_qes = verified_signatures.select { |signature| trusted_qes_signature?(signature, timestamps:) }
        # DocTS proves existence, not approval of changes to signed content.
        accepted = verified_signatures.select do |signature|
          if signature.sub_filter == 'ETSI.RFC3161'
            trusted_timestamps.include?(signature) &&
              (trusted_ranges.nil? || trusted_ranges.include?(signature.byte_range))
          elsif trusted_ranges
            trusted_ranges.include?(signature.byte_range)
          else
            (signature.sub_filter == 'adbe.pkcs7.detached' && trusted_signatures.include?(signature)) ||
              trusted_qes.include?(signature)
          end
        end
        last_signature = accepted.reject { |signature| signature.sub_filter == 'ETSI.RFC3161' }
                                 .max_by(&:signed_end)
        timestamp_ranges = (accepted & trusted_timestamps).map(&:byte_range)
        has_unsigned_changes = last_signature &&
                               unsigned_changes?(document, io, last_signature.signed_end,
                                                 allow_dss_changes:, timestamp_ranges:)

        signatures.map do |signature|
          build_signature(signature, trusted_certs,
                          verified: verified_signatures.include?(signature),
                          trusted: trusted_signatures.include?(signature) || trusted_qes.include?(signature),
                          tsa_trusted: trusted_timestamps.include?(signature),
                          modified: !!has_unsigned_changes && signature == last_signature)
        end
      end
    end
  end

  def trusted_qes_signature?(signature, timestamps: [], at: Time.current)
    return false unless signature.sub_filter == 'ETSI.CAdES.detached'

    pkcs7 = OpenSSL::PKCS7.new(signature.contents)
    signer = signer_certificate(pkcs7)
    return false unless signer && Qes::CertificateInfo.new(signer).signing_leaf?

    chain = (pkcs7.certificates || []).reject { |cert| cert.to_der == signer&.to_der }

    timestamp_time = timestamps.filter_map { |range, time| time if range[1] >= signature.signed_end }.min
    evidence_time = [timestamp_time, Qes::TimestampToken.signature_time(pkcs7, at:)].compact.min

    Qes::Validator.trusted_chain?(signer, chain, Qes.trust_roots, at: evidence_time || at)
  end

  def trusted_timestamp?(signature, io)
    return false unless signature.sub_filter == 'ETSI.RFC3161'

    Qes::TimestampToken.verify(OpenSSL::PKCS7.new(signature.contents), signed_data(io, signature.byte_range))
  end

  def verified_signature?(signature, io, trusted_certs)
    return false unless covers_signed_revision?(signature, io)

    pkcs7 = OpenSSL::PKCS7.new(signature.contents)

    if signature.sub_filter == 'ETSI.RFC3161'
      data = signed_data(io, signature.byte_range)
      verify_timestamp(pkcs7, data)
    else
      verify_contents(pkcs7, signed_data(io, signature.byte_range), trusted_certs)
    end
  rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::Timestamp::TimestampError,
         OpenSSL::ASN1::ASN1Error
    false
  end

  def verify_timestamp(pkcs7, signed_data)
    Qes::TimestampToken.intact?(pkcs7, signed_data)
  rescue OpenSSL::Timestamp::TimestampError, OpenSSL::ASN1::ASN1Error
    false
  end

  def build_signature(signature, trusted_certs, verified:, trusted:, modified:, tsa_trusted: false)
    pkcs7 = OpenSSL::PKCS7.new(signature.contents)

    SignatureStruct.new(
      messages: build_messages(pkcs7, verified, trusted_certs, modified, trusted:),
      reason: signature.reason,
      signing_time: signing_time(pkcs7, signature),
      common_name: common_name(pkcs7),
      type: signature.sub_filter,
      verified: verified,
      trusted: trusted,
      tsa_trusted: tsa_trusted,
      modified: modified
    )
  rescue OpenSSL::PKCS7::PKCS7Error
    SignatureStruct.new(
      messages: [MessageStruct.new(text: I18n.t('signature_verification_failed'), status: :error)],
      reason: signature.reason,
      signing_time: parse_time(signature.time),
      type: signature.sub_filter,
      verified: false,
      trusted: false,
      tsa_trusted: false,
      modified: false
    )
  end

  def build_messages(pkcs7, verified, trusted_certs, has_unsigned_changes, trusted: false)
    messages =
      if verified
        [MessageStruct.new(text: I18n.t('signature_valid'), status: :success),
         certificate_message(pkcs7, trusted_certs, trusted:)]
      else
        [MessageStruct.new(text: I18n.t('signature_verification_failed'), status: :error)]
      end

    if has_unsigned_changes
      messages << MessageStruct.new(text: I18n.t('contains_unsigned_changes_after_the_last_signature'),
                                    status: :warning)
    end

    messages << MessageStruct.new(text: "Certificate chain: #{certificate_chain(pkcs7).join(' -> ')}")
  end

  def certificate_message(_pkcs7, _trusted_certs, trusted: false)
    if trusted
      MessageStruct.new(text: I18n.t('signed_with_trusted_certificate'), status: :success)
    else
      MessageStruct.new(text: I18n.t('signed_with_external_certificate'), status: :error)
    end
  end

  def trusted_signature?(signature, trusted_certs)
    pkcs7 = OpenSSL::PKCS7.new(signature.contents)
    if signature.sub_filter == 'ETSI.CAdES.detached'
      signer = signer_certificate(pkcs7)
      return false unless signer && Qes::CertificateInfo.new(signer).signing_leaf?
    end

    trusted_certificate?(pkcs7, trusted_certs)
  rescue OpenSSL::PKCS7::PKCS7Error
    false
  end

  def trusted_certificate?(pkcs7, trusted_certs)
    public_key = signer_certificate(pkcs7)&.public_key&.to_der

    trusted_certs.any? { |e| e.public_key.to_der == public_key }
  end

  def verify_contents(pkcs7, signed_data, trusted_certs)
    return false if digest_algorithms(pkcs7).blank?

    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.purpose = OpenSSL::X509::PURPOSE_SMIME_SIGN
    store.verify_callback = ->(_success, _context) { true }
    trusted_certs.each { |cert| store.add_cert(cert) }

    pkcs7.verify(pkcs7.certificates, store, signed_data,
                 OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY)
  end

  def digest_algorithms(pkcs7)
    OpenSSL::ASN1.decode(pkcs7.to_der).value[1].value[0].value[1].value
  end

  def common_name(pkcs7)
    cert = signer_certificate(pkcs7)

    return if cert.nil?

    cert.subject.to_a.assoc(COMMON_NAME)&.dig(1)
  end

  def signer_certificate(pkcs7)
    info = pkcs7.signers.first

    pkcs7.certificates&.find { |cert| cert.issuer == info.issuer && cert.serial == info.serial }
  end

  def certificate_chain(pkcs7)
    signer = signer_certificate(pkcs7)

    return [] if signer.nil?

    certs = [signer]

    while (issuer = pkcs7.certificates.find { |cert| cert.subject == certs.last.issuer })
      break if certs.include?(issuer)

      certs << issuer
    end

    certs.map { |cert| cert.subject.to_a.assoc(COMMON_NAME)&.dig(1) }
  end

  def signing_time(pkcs7, signature)
    cms_signing_time(pkcs7) || parse_time(signature.time)
  end

  def cms_signing_time(pkcs7)
    pkcs7.signers.first&.signed_time
  rescue StandardError
    nil
  end

  def parse_time(value)
    return if value.blank?

    time = value.delete("'").delete_prefix('D:')
    offset = time[14..].to_s

    Time.strptime("#{time.first(14)}#{offset.start_with?('+', '-') ? offset : '+0000'}", TIME_FORMAT)
  end

  def covers_signed_revision?(signature, io)
    byte_range = signature.byte_range

    return false if byte_range.size != 4 || byte_range.any?(&:negative?) || byte_range[0].positive?
    return false if signature.signed_end > io.size

    byte_range[2] == byte_range[1] + (signature.contents.bytesize * 2) + 2
  end

  def unsigned_changes?(_document, io, signed_end, allow_dss_changes: true, timestamp_ranges: [])
    return signed_end < io.size unless allow_dss_changes

    io.rewind
    !Qes::RevisionChanges.allowed?(io.read, signed_end, timestamp_ranges:)
  end

  def signed_data(io, byte_range)
    byte_range.each_slice(2).map do |offset, length|
      io.seek(offset)
      io.read(length.clamp(0, [io.size - offset, 0].max))
    end.join
  end
end
