# frozen_string_literal: true

require 'rails_helper'

# LTV (SPEC § 7.4): CRL pro DSS slovník a URL z certifikátu se smí
# stahovat jen z allowlistu (SSRF ochrana).
RSpec.describe Qes::Ltv do
  before { QesHelpers.configure! }

  def issue_certificate(name, issuer: nil, issuer_key: nil)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.current - 3600
    cert.not_after = Time.current + 3600
    cert.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end

  def issue_crl(issuer, key, revoked: [], last_update: Time.current - 60, next_update: Time.current + 3600)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = issuer.subject
    crl.last_update = last_update
    crl.next_update = next_update
    revoked.each do |cert|
      entry = OpenSSL::X509::Revoked.new
      entry.serial = cert.serial
      entry.time = Time.current - 60
      crl.add_revoked(entry)
    end
    crl.sign(key, OpenSSL::Digest.new('SHA256'))

    crl
  end

  describe 'CRL freshness and chain scope' do
    let(:root_pair) { issue_certificate('Root') }
    let(:root_key) { root_pair.first }
    let(:root) { root_pair.last }
    let(:intermediate_pair) { issue_certificate('Intermediate', issuer: root, issuer_key: root_key) }
    let(:intermediate_key) { intermediate_pair.first }
    let(:intermediate) { intermediate_pair.last }
    let(:leaf_pair) { issue_certificate('Leaf', issuer: intermediate, issuer_key: intermediate_key) }
    let(:leaf) { leaf_pair.last }

    before { allow(Qes).to receive(:trust_roots).and_return([root]) }

    it 'rejects expired and future CRLs, allowing a small clock skew' do
      [
        issue_crl(root, root_key, next_update: Time.current - 600),
        issue_crl(root, root_key, last_update: Time.current + 600)
      ].each do |crl|
        expect { described_class.validate_crl!(crl, intermediate, root) }
          .to raise_error(Qes::Ltv::FetchError, /validity period/)
      end

      crl = issue_crl(root, root_key, next_update: Time.current - 60)
      expect { described_class.validate_crl!(crl, intermediate, root) }.not_to raise_error
    end

    it 'collects both CRLs with the root supplied only by server configuration' do
      leaf_crl = issue_crl(intermediate, intermediate_key)
      root_crl = issue_crl(root, root_key)
      allow(described_class).to receive(:crl_urls).with(leaf).and_return(['https://crl.test/leaf'])
      allow(described_class).to receive(:crl_urls).with(intermediate).and_return(['https://crl.test/intermediate'])
      allow(described_class).to receive(:fetch_first_crl).with(['https://crl.test/leaf']).and_return(leaf_crl)
      allow(described_class).to receive(:fetch_first_crl).with(['https://crl.test/intermediate']).and_return(root_crl)

      expect(described_class.collect_revocation_data(leaf, chain: [intermediate]))
        .to eq([leaf_crl, root_crl])
    end

    it 'rejects a revoked intermediate even when the leaf is not revoked' do
      crls = [issue_crl(intermediate, intermediate_key), issue_crl(root, root_key, revoked: [intermediate])]

      expect { described_class.check_revoked!(leaf, chain: [intermediate.to_der], crls:) }
        .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:revoked) }
    end

    it 'does not match a serial in a CRL from another issuer' do
      crl = issue_crl(root, root_key, revoked: [leaf])

      expect { described_class.check_revoked!(leaf, chain: [intermediate], crls: [crl]) }.not_to raise_error
    end

    it 'rejects fresh revocation at completion before building or embedding the CMS' do
      earlier = issue_crl(intermediate, intermediate_key)
      described_class.check_revoked!(leaf, chain: [intermediate], crls: [earlier])
      fresh = issue_crl(intermediate, intermediate_key, revoked: [leaf])
      allow(described_class).to receive(:fetch_crls).and_return([fresh])
      session = double('session', state: 'awaiting_signature', certificate: leaf,
                                  signed_attrs_der: 'signed attributes', hash_algorithm: 'SHA256',
                                  certificate_chain: [leaf, intermediate].map { |cert| Base64.strict_encode64(cert.to_der) })
      provider = Qes::Providers::MobileApp.new(session)
      signature = leaf_pair.first.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)

      expect(provider).not_to receive(:build_cms)
      expect(provider).not_to receive(:embed)
      expect { provider.complete!(signature) }
        .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:revoked) }
    end
  end

  describe '.private_address?' do
    %w[100.64.0.0 100.127.255.255 0.0.0.0 0.255.255.255 169.254.1.1
       10.0.0.1 172.16.0.1 192.168.1.1 127.0.0.1 :: ::1 fc00::1 fdff::1 fe80::1
       ::ffff:192.168.1.1 ::ffff:100.64.0.1 ::ffff:127.0.0.1 ::ffff:0.0.0.0
       ::ffff:169.254.1.1].each do |address|
      it "rejects #{address}" do
        expect(described_class.private_address?(address)).to be true
      end
    end

    %w[100.63.255.255 100.128.0.0 1.1.1.1 2606:4700:4700::1111 ::ffff:1.1.1.1].each do |address|
      it "allows the public address #{address}" do
        expect(described_class.private_address?(address)).to be false
      end
    end
  end

  describe '.validate_url!' do
    it 'allows an explicitly allowlisted host over http (testy)' do
      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .not_to raise_error
    end

    it 'rejects a host outside the allowlist' do
      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .not_to raise_error
      expect { described_class.validate_url!(URI.parse('http://169.254.169.254/latest/meta-data/')) }
        .to raise_error(Qes::Ltv::FetchError, /not in QES_LTV_ALLOWED_HOSTS/)
    end

    it 'requires https for a public host when no allowlist is set' do
      Qes::Config[:ltv_allowed_hosts] = nil

      expect { described_class.validate_url!(URI.parse('http://example.com/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError, /https/)
    end

    it 'rejects a private address when no allowlist is set' do
      Qes::Config[:ltv_allowed_hosts] = nil

      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError)
      expect { described_class.validate_url!(URI.parse('https://127.0.0.1/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError, /private address/)
      expect { described_class.validate_url!(URI.parse('https://169.254.169.254/latest/meta-data/')) }
        .to raise_error(Qes::Ltv::FetchError, /private address/)
    end

    it 'rejects unsupported schemes' do
      expect { described_class.validate_url!(URI.parse('file:///etc/passwd')) }
        .to raise_error(Qes::Ltv::FetchError, /scheme/)
    end
  end
end
