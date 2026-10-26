# frozen_string_literal: true

module Qes
  # Parsuje X.509 certifikát podepisujícího a určuje úroveň podpisu z QCStatements
  # (SPEC § 8): `QcCompliance` → AdES, `QcCompliance` + `QcSSCD` → QES.
  class CertificateInfo
    QC_STATEMENTS_OID = '1.3.6.1.5.5.7.1.3'
    QC_COMPLIANCE_OID = '0.4.0.1862.1.1'
    QC_SSCD_OID = '0.4.0.1862.1.4'

    QC_STATEMENT_NAMES = {
      QC_COMPLIANCE_OID => 'QcCompliance',
      QC_SSCD_OID => 'QcSSCD'
    }.freeze

    DIGITAL_SIGNATURE_BIT = 0

    attr_reader :certificate

    def self.parse(der)
      new(OpenSSL::X509::Certificate.new(der))
    rescue OpenSSL::X509::CertificateError, ArgumentError, TypeError
      raise ClientError.new(:invalid_certificate, 'Certificate could not be parsed')
    end

    def initialize(certificate)
      @certificate = certificate
    end

    def qc_statements
      extension = find_extension('1.3.6.1.5.5.7.1.3', 'qcStatements')
      return [] if extension.blank?

      statements = OpenSSL::ASN1.decode(extension.value_der)
      Array(statements.value).filter_map do |statement|
        next unless statement.is_a?(OpenSSL::ASN1::Sequence)

        oid = statement.value.first
        QC_STATEMENT_NAMES[oid.value] if oid.respond_to?(:value)
      end
    rescue OpenSSL::ASN1::ASN1Error
      []
    end

    def qc_compliance?
      qc_statements.include?('QcCompliance')
    end

    def qc_sscd?
      qc_statements.include?('QcSSCD')
    end

    def level
      return 'none' unless qc_compliance?

      qc_sscd? ? 'qes' : 'ades'
    end

    def key_usage
      extension = find_extension('2.5.29.15', 'keyUsage')
      return nil if extension.blank?

      OpenSSL::ASN1.decode(extension.value_der).value.unpack1('B*')
    rescue OpenSSL::ASN1::ASN1Error
      nil
    end

    def digital_signature?
      usage = key_usage
      usage&.[](0) == '1'
    end

    def content_commitment?
      key_usage&.[](1) == '1'
    end

    def signing_leaf?
      return false unless digital_signature? || content_commitment?

      constraints = find_extension('2.5.29.19', 'basicConstraints')
      return true unless constraints

      sequence = OpenSSL::ASN1.decode(constraints.value_der)
      return false unless sequence.is_a?(OpenSSL::ASN1::Sequence)

      sequence.value.none? { |item| item.is_a?(OpenSSL::ASN1::Boolean) && item.value }
    rescue OpenSSL::ASN1::ASN1Error
      false
    end

    def find_extension(oid, short_name)
      certificate.extensions.find { |ext| ext.oid == oid || ext.oid == short_name }
    end

    def key_type
      case certificate.public_key
      when OpenSSL::PKey::RSA then 'rsa'
      when OpenSSL::PKey::EC then 'ecdsa'
      end
    end

    def key_size
      case certificate.public_key
      when OpenSSL::PKey::RSA then certificate.public_key.n.num_bits
      when OpenSSL::PKey::EC then certificate.public_key.group.degree
      end
    end

    def expired?(at = Time.current)
      at < certificate.not_before || at > certificate.not_after
    end

    def serial_hex
      "0x#{certificate.serial.to_s(16).upcase}"
    end

    def to_h
      {
        subject: certificate.subject.to_s,
        issuer: certificate.issuer.to_s,
        serial: serial_hex,
        not_before: certificate.not_before.utc.iso8601,
        not_after: certificate.not_after.utc.iso8601,
        level: level,
        qc_statements: qc_statements,
        key_type: key_type,
        key_size: key_size,
        key_usage: key_usage
      }
    end

    # Zkontroluje certifikát proti požadované úrovni a umístění klíče (SPEC § 5.2).
    # Vrací hash pro `certificate_info`; při chybě vyhodí `Qes::ClientError`.
    def validate!(level_required:, key_location:, at: Time.current)
      unless signing_leaf?
        raise ClientError.new(:invalid_certificate, 'A non-CA signing certificate with signing key usage is required')
      end
      raise ClientError.new(:certificate_expired, 'Certificate is not valid at this time') if expired?(at)
      raise ClientError.new(:unsupported_key, "Unsupported key type #{key_type.inspect}") unless %w[rsa ecdsa].include?(key_type)
      raise ClientError.new(:unsupported_key, 'Key too small') if key_type == 'rsa' && key_size < 2048

      if key_location == 'phone_keystore' && qc_sscd?
        raise ClientError.new(:level_mismatch, 'QcSSCD certificate cannot be used from phone keystore')
      end

      if key_location == 'card' && !qc_sscd?
        raise ClientError.new(:level_mismatch, 'Card certificate must be QcSSCD')
      end

      if level_required == 'qes' && !qc_sscd?
        raise ClientError.new(:qes_required_qscd, 'QES requires a QcSSCD certificate')
      end

      raise ClientError.new(:not_qualified, 'Certificate is not qualified') unless qc_compliance?

      to_h
    end
  end
end
