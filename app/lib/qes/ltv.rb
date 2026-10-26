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
    # Bez CRL DP smí být LTV nepovinné. Chyba existujícího DP vždy zastaví podpis.
    def fetch_crls(certificate, chain: [])
      collect_revocation_data(certificate, chain:)
    rescue FetchError => e
      raise ClientError.new(:ltv_unavailable, e.message)
    rescue OpenSSL::X509::CertificateError => e
      raise ClientError.new(:invalid_certificate, e.message)
    end

    def collect_revocation_data(certificate, chain: [])
      certs = [certificate, *chain].flatten.compact.map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      end
      crls = collect_crls(certs)

      if crls.empty?
        raise FetchError, 'No revocation information available' if Qes::Config[:require_ltv]

        return nil
      end

      crls
    end

    # Odmítne certifikát, který je v CRL uvedený jako revokovaný (SPEC § 15.2 N4).
    def check_revoked!(certificate, chain: [], crls: nil)
      crls ||= fetch_crls(certificate, chain:)
      if crls.blank? && Qes::Config[:require_ltv]
        raise FetchError, 'No revocation information available'
      end

      certs = [certificate, *chain].map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      end

      certs.each_with_index do |cert, index|
        next if index.positive? && self_signed?(cert)

        matching = Array(crls).select { |crl| crl.issuer == cert.issuer }
        if matching.empty? && crl_distribution_point?(cert)
          raise FetchError, 'No matching CRL available'
        end

        validate_crl_sequence!(matching)

        matching.each do |crl|
          issuer = issuer_for(cert, certs + Qes.trust_roots)
          validate_crl!(crl, cert, issuer)
          next unless crl.revoked.any? { |entry| entry.serial == cert.serial }

          raise ClientError.new(:revoked, 'Certificate is revoked')
        end
      end
    rescue FetchError => e
      raise ClientError.new(:ltv_unavailable, e.message)
    rescue OpenSSL::X509::CertificateError => e
      raise ClientError.new(:invalid_certificate, e.message)
    end

    def collect_crls(certs)
      certs.flatten.compact.each_with_index.filter_map do |cert, index|
        next if index.positive? && self_signed?(cert)

        urls = crl_urls(cert)
        next unless crl_distribution_point?(cert) || urls.present?

        raise FetchError, 'No usable CRL distribution point' if urls.empty?

        crl = fetch_first_crl(urls)
        issuer = issuer_for(cert, certs + Qes.trust_roots)

        validate_crl!(crl, cert, issuer)

        crl
      end
    end

    # CRL DP bývá v certifikátu víckrát (PostSignum); zkusí se všechny a použije
    # se CRL s nejvyšším `crlNumber` (nález 2.7).
    def fetch_first_crl(urls)
      crls = urls.filter_map do |url|
        fetch_crl(url)
      rescue FetchError => e
        Rails.logger.warn("[qes] CRL fetch failed: #{e.message}")
        nil
      end

      raise FetchError, 'No CRL could be fetched' if crls.empty?

      crls.max_by { |crl| crl_number(crl) || 0 }
    end

    def fetch_crl(url)
      uri = URI.parse(url)
      address = validate_url!(uri)
      body = +''
      http = Net::HTTP.new(uri.host, uri.port)
      http.ipaddr = address if address
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = FETCH_TIMEOUT
      http.read_timeout = FETCH_TIMEOUT

      http.start do |client|
        client.request_get(uri.request_uri) do |response|
          raise FetchError, "CRL fetch failed with status #{response.code}" unless response.is_a?(Net::HTTPSuccess)
          if response['Content-Length'].to_i > MAX_RESPONSE_BYTES
            raise FetchError, "CRL response too large (#{response['Content-Length']} B)"
          end

          response.read_body do |chunk|
            body << chunk
            raise FetchError, "CRL response too large (#{body.bytesize} B)" if body.bytesize > MAX_RESPONSE_BYTES
          end
        end
      end

      OpenSSL::X509::CRL.new(body)
    rescue OpenSSL::X509::CRLError, URI::InvalidURIError, SocketError, Timeout::Error, SystemCallError, OpenSSL::SSL::SSLError => e
      raise FetchError, "CRL fetch failed: #{e.class}"
    end

    # SSRF ochrana (SPEC § 7.4): URL je z certifikátu, tedy nedůvěryhodný vstup.
    # Host z `QES_LTV_ALLOWED_HOSTS` je explicitně povolený (i http pro testy),
    # jinak se vyžaduje https a veřejná adresa.
    # Vrací ověřenou IP adresu, na kterou se má spojení připíchnout. Tím se
    # zavře DNS-rebinding TOCTOU mezi kontrolou a `Net::HTTP.start` (nález 2.9).
    def validate_url!(uri)
      unless %w[http https].include?(uri.scheme)
        raise FetchError, "Unsupported CRL scheme #{uri.scheme.inspect}"
      end
      raise FetchError, 'CRL URL has no host' if uri.host.blank?

      addresses = resolved_addresses(uri.host)
      raise FetchError, "CRL host #{uri.host.inspect} has no address" if addresses.empty?

      unless allowed_hosts.any? { |host| host.casecmp?(uri.host) }
        if allowed_hosts.present?
          raise FetchError, "CRL host #{uri.host.inspect} is not in QES_LTV_ALLOWED_HOSTS"
        end
        raise FetchError, "CRL URL must use https (#{uri.host})" unless uri.scheme == 'https'
        if addresses.any? { |address| private_address?(address) }
          raise FetchError, "CRL host #{uri.host.inspect} resolves to a private address"
        end
      end

      addresses.first
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
      ip = ip.native if ip.ipv4_mapped?

      ip.loopback? || ip.private? || ip.link_local? ||
        %w[100.64.0.0/10 0.0.0.0/8 169.254.0.0/16 ::/128 fc00::/7].any? do |range|
          IPAddr.new(range).include?(ip)
        end
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

      validate_crl_scope!(crl, cert)
    end

    # Delta CRL by neměl projít jako plná CRL a IDP omezuje rozsah revokace
    # (nález 2.7). Neznámý rozsah je fail-closed.
    def validate_crl_scope!(crl, cert)
      raise FetchError, 'Delta CRLs are not supported' if crl_extension(crl, '2.5.29.27', 'deltaCRL')

      value = crl_extension(crl, '2.5.29.28', 'issuingDistributionPoint')
      return if value.blank?

      sequence = OpenSSL::ASN1.decode(value)
      raise FetchError, 'Invalid CRL distribution point scope' unless sequence.is_a?(OpenSSL::ASN1::Sequence)

      sequence.value.each do |node|
        next unless node.is_a?(OpenSSL::ASN1::ASN1Data)

        case node.tag
        when 0
          names = asn1_strings(node)
          if (names & crl_urls(cert)).empty?
            raise FetchError, 'CRL distribution point does not match certificate'
          end
        when 1
          raise FetchError, 'CRL only contains CA certificates' if node.value && !certificate_authority?(cert)
        when 2
          raise FetchError, 'CRL only contains user certificates' if node.value && certificate_authority?(cert)
        when 3
          raise FetchError, 'CRL reason scope is not supported'
        when 4
          raise FetchError, 'Indirect CRLs are not supported' if node.value
        when 5
          raise FetchError, 'CRL only contains attribute certificates' if node.value
        end
      end
    rescue OpenSSL::ASN1::ASN1Error
      raise FetchError, 'Invalid CRL distribution point scope'
    end

    # Monotónie `crlNumber` mezi CRL stejného issuera: novější `lastUpdate`
    # nesmí mít nižší číslo (nález 2.7). Chybějící číslo se přeskočí, protože
    # starší testovací CRL číslo nemají.
    def validate_crl_sequence!(crls)
      numbered = crls.select { |crl| crl_number(crl) }
                     .sort_by { |crl| crl.last_update || Time.at(0) }

      numbered.each_cons(2) do |older, newer|
        raise FetchError, 'CRL numbers are not monotonic' if crl_number(newer) < crl_number(older)
      end
    end

    def crl_extension(crl, oid, name)
      extension = crl.extensions.find { |ext| ext.oid == oid || ext.oid == name }
      extension&.value_der
    end

    def crl_number(crl)
      value = crl_extension(crl, '2.5.29.20', 'crlNumber')
      return if value.blank?

      OpenSSL::ASN1.decode(value).value
    rescue OpenSSL::ASN1::ASN1Error
      nil
    end

    def asn1_strings(node)
      value = node.respond_to?(:value) ? node.value : nil

      if node.is_a?(OpenSSL::ASN1::IA5String) || value.is_a?(String)
        [value]
      elsif value.is_a?(Array)
        value.flat_map { |child| asn1_strings(child) }
      else
        []
      end
    end

    def certificate_authority?(cert)
      value = cert.extensions.find { |ext| ext.oid == '2.5.29.19' || ext.oid == 'basicConstraints' }&.value_der
      return false if value.blank?

      sequence = OpenSSL::ASN1.decode(value)
      sequence.is_a?(OpenSSL::ASN1::Sequence) &&
        sequence.value.any? { |item| item.is_a?(OpenSSL::ASN1::Boolean) && item.value }
    rescue OpenSSL::ASN1::ASN1Error
      false
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

    def crl_distribution_point?(cert)
      cert.extensions.any? { |ext| [CRL_DISTRIBUTION_POINT_OID, 'crlDistributionPoints'].include?(ext.oid) }
    end

    def self_signed?(cert)
      cert.issuer == cert.subject
    end
  end
end
