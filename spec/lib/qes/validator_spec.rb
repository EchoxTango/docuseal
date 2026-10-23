# frozen_string_literal: true

require 'rails_helper'

# Důvěryhodnost certifikátu (SPEC § 5.2 a § 7.5): řetěz se musí ověřit
# i s intermediate CA a self-signed certifikát nesmí projít jako QES.
RSpec.describe Qes::Validator do
  it 'verifies a DigiCert timestamp token whose TSTInfo is in eContent' do
    token = File.binread(QesHelpers::TEST_DIR.join('fixtures', 'digicert-token.der'))
    pkcs7 = OpenSSL::PKCS7.new(token)

    expect(described_class.verify_timestamp(pkcs7, 'digest-test')).to be true
  end

  before { QesHelpers.configure! }

  def make_ca(subject, issuer_cert, issuer_key)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.current - 60
    cert.not_after = Time.current + 3650.days
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end

  def make_leaf(issuer_cert, issuer_key)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse('/C=CZ/O=QES/CN=Leaf')
    cert.issuer = issuer_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.current - 60
    cert.not_after = Time.current + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert
    cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end

  it 'trusts a leaf issued through an intermediate CA' do
    root_key, root = make_ca('/C=CZ/O=QES/CN=Root', nil, nil)
    int_key, int_cert = make_ca('/C=CZ/O=QES/CN=Intermediate', root, root_key)
    _leaf_key, leaf = make_leaf(int_cert, int_key)

    expect(described_class.trusted_chain?(leaf, [int_cert], [root])).to be true
    expect(described_class.trusted_chain?(leaf, [], [root])).to be false
    expect(described_class.trusted_chain?(leaf, [int_cert], [])).to be false
  end

  it 'rejects a self-signed certificate even with QCStatements' do
    _key, cert = QesHelpers.self_signed_qc_sscd_certificate

    expect(described_class.trusted_chain?(cert, [], QesHelpers.trust_roots)).to be false
    expect { described_class.verify_chain!(cert, [], QesHelpers.trust_roots) }
      .to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:not_trusted) }
  end

  it 'rejects verification without configured trust roots' do
    _key, cert = QesHelpers.self_signed_qc_sscd_certificate

    expect { described_class.verify_chain!(cert, [], []) }
      .to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:not_trusted) }
  end

  it 'accepts a certificate issued directly by the trust root' do
    expect(described_class.verify_chain!(QesHelpers.certificate, QesHelpers.chain, QesHelpers.trust_roots))
      .to be_nil
  end
end
