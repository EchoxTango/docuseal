# frozen_string_literal: true

require 'net/http'
require 'resolv'
require 'ipaddr'
require 'uri'

module Qes
  # LTV: revokační data (CRL) pro DSS slovník (PAdES-LT, SPEC § 7.4).
  # CMS LTV (`id-aa-ets-revocationValues`) se nepoužívá — HexaPDF 1.7 ho neumí
  # a pyHanko ho nečte; data jdou do DSS s VRI (viz `Qes::Dss`).
  module Ltv
    CRL_DISTRIBUTION_POINT_OID = '2.5.29.31'
    CLOCK_SKEW = 300
    FETCH_TIMEOUT = 10
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    class FetchError < StandardError; end

    module_function

    # CRL objekty pro kontrolu revokace (SPEC § 7.4).
    # Bez LTV (nevyžadováno a nedostupné) vrací nil.
    def fetch_crls(certificate, chain: [])
      collect_revocation_data(certificate, chain:)
    rescue FetchError => e
      raise ClientError.new(:ltv_unavailable, e.message) if Qes::Config[:require_ltv]

      Rails.logger.warn("[qes] ltv unavailable: #{e.message}")

      nil
    rescue OpenSSL::X509::CertificateError
      # Malformed cert se parsuje až v `CertificateInfo.parse` (422 invalid_certificate).
      nil
    end

    def collect_revocation_data(certificate, chain: [])
      certs = [certificate, *chain].flatten.compact.map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      end
      crls = collect_crls(certs)

      raise FetchError, 'No revocation information available' if crls.empty?

      crls
    end

    # Odmítne certifikát, který je v CRL uvedený jako revokovaný (SPEC § 15.2 N4).
    def check_revoked!(certificate, chain: [], crls: nil)
      crls ||= fetch_crls(certificate, chain:)
      return if crls.blank?

      certs = [certificate, *chain].map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      end

      certs.each do |cert|
        next if self_signed?(cert)

        crls.each do |crl|
          next unless crl.issuer == cert.issuer

          issuer = issuer_for(cert, certs + Qes.trust_roots)
          validate_crl!(crl, cert, issuer)
          next unless crl.revoked.any? { |entry| entry.serial == cert.serial }

          raise ClientError.new(:revoked, 'Certificate is revoked')
        end
      end
    end

    def collect_crls(certs)
      certs.flatten.compact.filter_map do |cert|
        next if self_signed?(cert)

        urls = crl_urls(cert)
        next if urls.empty?

        crl = fetch_first_crl(urls)
        issuer = issuer_for(cert, certs + Qes.trust_roots)

        validate_crl!(crl, cert, issuer)

        crl
      end
    end

    # CRL DP bývá v certifikátu víckrát (PostSignum); zkusí se všechny.
    def fetch_first_crl(urls)
      urls.each do |url|
        return fetch_crl(url)
      rescue FetchError => e
        Rails.logger.warn("[qes] CRL fetch failed: #{e.message}")
      end

      raise FetchError, 'No CRL could be fetched'
    end

    def fetch_crl(url)
      uri = URI.parse(url)

      validate_url!(uri)

      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                open_timeout: FETCH_TIMEOUT, read_timeout: FETCH_TIMEOUT) do |http|
        http.get(uri.request_uri)
      end

      raise FetchError, "CRL fetch failed with status #{response.code}" unless response.is_a?(Net::HTTPSuccess)
      if response.body.to_s.bytesize > MAX_RESPONSE_BYTES
        raise FetchError, "CRL response too large (#{response.body.bytesize} B)"
      end

      OpenSSL::X509::CRL.new(response.body)
    rescue OpenSSL::X509::CRLError, URI::InvalidURIError, SocketError, Timeout::Error, SystemCallError, OpenSSL::SSL::SSLError => e
      raise FetchError, "CRL fetch failed: #{e.class}"
    end

    # SSRF ochrana (SPEC § 7.4): URL je z certifikátu, tedy nedůvěryhodný vstup.
    # Host z `QES_LTV_ALLOWED_HOSTS` je explicitně povolený (i http pro testy),
    # jinak se vyžaduje https a veřejná adresa.
    def validate_url!(uri)
      unless %w[http https].include?(uri.scheme)
        raise FetchError, "Unsupported CRL scheme #{uri.scheme.inspect}"
      end
      raise FetchError, 'CRL URL has no host' if uri.host.blank?
      return if allowed_hosts.any? { |host| host.casecmp?(uri.host) }

      if allowed_hosts.present?
        raise FetchError, "CRL host #{uri.host.inspect} is not in QES_LTV_ALLOWED_HOSTS"
      end
      raise FetchError, "CRL URL must use https (#{uri.host})" unless uri.scheme == 'https'
      if resolved_addresses(uri.host).any? { |address| private_address?(address) }
        raise FetchError, "CRL host #{uri.host.inspect} resolves to a private address"
      end
    end

    def allowed_hosts
      Array(Qes::Config[:ltv_allowed_hosts].to_s.split(',')).map(&:strip).reject(&:blank?)
    end

    def resolved_addresses(host)
      [IPAddr.new(host).to_s]
    rescue IPAddr::InvalidAddressError
      Resolv.getaddresses(host)
    end

    def private_address?(address)
      ip = IPAddr.new(address)

      ip.loopback? || ip.private? || ip.link_local?
    rescue IPAddr::InvalidAddressError
      true
    end

    def issuer_for(cert, candidates)
      candidates.find { |candidate| candidate.subject == cert.issuer && cert.verify(candidate.public_key) }
    end

    def validate_crl!(crl, cert, issuer)
      unless crl.issuer == cert.issuer && issuer && crl.verify(issuer.public_key)
        raise FetchError, 'CRL does not match certificate issuer'
      end

      now = Time.current
      unless crl.last_update && crl.next_update &&
             crl.last_update <= now + CLOCK_SKEW && crl.next_update >= now - CLOCK_SKEW
        raise FetchError, 'CRL is outside its validity period'
      end
    end

    def crl_urls(cert)
      extension = cert.extensions.find do |ext|
        ext.oid == CRL_DISTRIBUTION_POINT_OID || ext.oid == 'crlDistributionPoints'
      end
      return [] if extension.blank?

      urls = []
      walk = lambda do |node|
        value = node.respond_to?(:value) ? node.value : nil

        if node.is_a?(OpenSSL::ASN1::IA5String) || value.is_a?(String)
          urls << value
        elsif value.is_a?(Array)
          value.each { |child| walk.call(child) }
        end
      end
      walk.call(OpenSSL::ASN1.decode(extension.value_der))
      urls
    rescue OpenSSL::ASN1::ASN1Error
      []
    end

    def self_signed?(cert)
      cert.issuer == cert.subject
    end
  end
end
