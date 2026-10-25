# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::TimestampToken do
  before { QesHelpers.configure! }

  let(:data) { 'timestamped document' }
  let(:token) do
    OpenSSL::PKCS7.new(QesHelpers.build_timestamp_token(
      OpenSSL::Digest.digest('SHA256', data),
      key: QesHelpers.tsa_key, certificate: QesHelpers.tsa_certificate
    ))
  end

  it 'keeps integrity separate from trust when no TSA roots are configured' do
    expect(described_class.intact?(token, data)).to be true
    expect(described_class.intact?(token, 'another document')).to be false
    expect(described_class.verify(token, data)).to be false
    expect(described_class.verify(token, 'another document')).to be false
    expect(described_class.verified_time(token, data)).to be_nil
  end

  it 'requires the configured TSA chain and timestamp signing purpose' do
    expect(described_class.verify(token, data, trust_roots: [QesHelpers.tsa_root_certificate])).to be true
    expect(described_class.verify(token, data, trust_roots: QesHelpers.trust_roots)).to be false
  end

  it 'checks old timestamp integrity without trusting its TSA or accepting a wrong imprint' do
    allow(Qes).to receive(:tsa_trust_roots).and_return(QesHelpers.trust_roots)

    expect(described_class.verify(token, data)).to be false
    expect(described_class.intact?(token, data)).to be true
    expect(described_class.intact?(token, 'changed document')).to be false
  end

  it 'does not fall back to untrusted mode when configured files are missing' do
    Qes::Config[:tsa_trust_roots] = 'missing-tsa-root.pem'

    expect(described_class.verify(token, data)).to be false
  end

  it 'rejects a trusted certificate without the timestamping EKU' do
    key = QesHelpers.tsa_key
    certificate = OpenSSL::X509::Certificate.new(QesHelpers.tsa_certificate.to_der)
    certificate.extensions = certificate.extensions.reject { |extension| extension.oid == 'extendedKeyUsage' }
    certificate.sign(QesHelpers.tsa_root_key_and_certificate.first, OpenSSL::Digest.new('SHA256'))
    other = OpenSSL::PKCS7.new(QesHelpers.build_timestamp_token(
      OpenSSL::Digest.digest('SHA256', data), key:, certificate:
    ))

    expect(described_class.verify(other, data, trust_roots: [QesHelpers.tsa_root_certificate])).to be false
  end

  it 'rejects future timestamp evidence' do
    future = OpenSSL::PKCS7.new(QesHelpers.build_timestamp_token(
      OpenSSL::Digest.digest('SHA256', data), key: QesHelpers.tsa_key,
      certificate: QesHelpers.tsa_certificate, at: Time.current + 600
    ))

    expect(described_class.intact?(future, data)).to be true
    expect(described_class.verify(future, data, trust_roots: [QesHelpers.tsa_root_certificate])).to be false
  end

  it 'loads comma-separated PEM paths' do
    Qes::Config[:tsa_trust_roots] = " #{QesHelpers.pki_path('root.crt')}, #{QesHelpers.pki_path('root.crt')} "

    expect(Qes.tsa_trust_roots.map(&:to_der)).to eq(QesHelpers.trust_roots.map(&:to_der) * 2)
  end
end
