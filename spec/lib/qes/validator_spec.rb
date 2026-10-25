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

  describe 'historical chain validation' do
    let(:root_pair) { make_ca('/CN=Historical Root', nil, nil) }
    let(:root) { root_pair.last }
    let(:leaf_pair) { make_leaf(root, root_pair.first) }
    let(:leaf) { leaf_pair.last }
    let(:pkcs) { OpenSSL::PKCS12.create('test', 'historical', leaf_pair.first, leaf, [root]) }
    let(:later) { leaf.not_after + 3600 }

    before do
      allow(Qes).to receive(:trust_roots).and_return([root])
      allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    end

    it 'uses current time without timestamp evidence, ignoring claimed signingTime' do
      pdf = QesHelpers.signed_pdf(pkcs:)
      report = described_class.call(pdf, trust_roots: [root], at: later)

      expect(report[:intact]).to be true
      expect(report[:trusted]).to be false
      expect(report[:ok]).to be false
      expect(report[:signatures].first).to include(time_source: 'current', validated_at_time: later.utc.iso8601)
    end

    it 'uses a verified signature timestamp after the signing certificate expires' do
      allow_any_instance_of(Submissions::TimestampHandler).to receive(:sign) do |_handler, io, byte_range|
        QesHelpers.timestamp_token(io, byte_range)
      end
      pdf = QesHelpers.signed_pdf(pkcs:, tsa_url: 'http://tsa.test')
      report = described_class.call(pdf, trust_roots: [root], at: later)
      signature = report[:signatures].first

      expect(report[:ok]).to be true
      expect(signature).to include(trusted: true, time_source: 'timestamp', tsa_trusted: true)
      expect(Time.iso8601(signature[:validated_at_time])).to be_between(leaf.not_before, leaf.not_after)
    end

    it 'uses a later covering DocTS after both the signer and TSA certificate expire' do
      pdf = QesHelpers.signed_pdf(pkcs:)
      allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign) do |_handler, io, byte_range|
        QesHelpers.timestamp_token(io, byte_range)
      end
      stamped, state = Qes::DocTimestamp.apply(pdf, tsa_url: 'http://tsa.test')
      expect(state).to eq('applied')

      at = [later, QesHelpers.tsa_certificate.not_after + 60].max
      report = described_class.call(stamped, trust_roots: [root], at:)
      expect(report[:ok]).to be true
      expect(report[:signatures].first).to include(trusted: true, time_source: 'timestamp', tsa_trusted: true)
      expect(Time.iso8601(report[:signatures].first[:validated_at_time])).to be < leaf.not_after
    end

    it 'keeps an earlier expired signer trusted when a new signer appends a signature' do
      pdf = QesHelpers.signed_pdf(pkcs:)
      allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign) do |_handler, io, byte_range|
        QesHelpers.timestamp_token(io, byte_range)
      end
      stamped, state = Qes::DocTimestamp.apply(pdf, tsa_url: 'http://tsa.test')
      expect(state).to eq('applied')

      travel_to(later) do
        key, certificate = make_leaf(root, root_pair.first)
        document = HexaPDF::Document.new(io: StringIO.new(stamped))
        output = StringIO.new
        document.sign(output, certificate:, key:, certificate_chain: [root], signature_type: :pades,
                              write_options: { validate: false })

        report = described_class.call(output.string, trust_roots: [root])

        expect(report[:ok]).to be true
        expect(report[:signatures].first).to include(trusted: true, time_source: 'timestamp')
        expect(report[:signatures].last).to include(trusted: true, time_source: 'current', coverage: 'full')
      end
    end

    it 'does not use an earlier DocTS as evidence for a later signature' do
      document = HexaPDF::Document.new
      document.pages.add
      output = StringIO.new
      document.write(output)
      allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign) do |_handler, io, byte_range|
        QesHelpers.timestamp_token(io, byte_range)
      end
      stamped, state = Qes::DocTimestamp.apply(output.string, tsa_url: 'http://tsa.test')
      expect(state).to eq('applied')
      document = HexaPDF::Document.new(io: StringIO.new(stamped))
      signed = StringIO.new
      document.sign(signed, certificate: leaf, key: leaf_pair.first, certificate_chain: [root],
                            signature_type: :pades, write_options: { validate: false })

      report = described_class.call(signed.string, trust_roots: [root], at: later)

      expect(report[:trusted]).to be false
      expect(report[:signatures].last).to include(time_source: 'current', trusted: false)
    end

    it 'does not use an untrusted timestamp to restore an expired certificate' do
      allow_any_instance_of(Submissions::TimestampHandler).to receive(:sign) do |_handler, io, byte_range|
        QesHelpers.timestamp_token(io, byte_range)
      end
      pdf = QesHelpers.signed_pdf(pkcs:, tsa_url: 'http://tsa.test')
      allow(Qes).to receive(:tsa_trust_roots).and_return([root])

      report = described_class.call(pdf, trust_roots: [root], at: later)

      expect(report[:trusted]).to be false
      expect(report[:signatures].first).to include(time_source: 'current', tsa_trusted: false)
    end

    it 'does not use a timestamp whose imprint belongs to another signature' do
      token = QesHelpers.build_timestamp_token(OpenSSL::Digest.digest('SHA256', 'other signature'),
                                               key: QesHelpers.tsa_key, certificate: QesHelpers.tsa_certificate)
      allow_any_instance_of(Submissions::TimestampHandler).to receive(:sign).and_return(token)
      pdf = QesHelpers.signed_pdf(pkcs:, tsa_url: 'http://tsa.test')

      report = described_class.call(pdf, trust_roots: [root], at: later)

      expect(report[:trusted]).to be false
      expect(report[:signatures].first[:time_source]).to eq('current')
    end
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
