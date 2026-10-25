# frozen_string_literal: true

require 'rails_helper'

# Dokumentový timestamp (PAdES-LTA, SPEC § 7.6): nová inkrementální revize
# s `DocTimeStamp`/`ETSI.RFC3161`; kryje DSS i pečeť.
RSpec.describe Qes::DocTimestamp do
  before do
    QesHelpers.configure!
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
  end

  def blank_pdf
    pdf = HexaPDF::Document.new
    pdf.pages.add
    io = StringIO.new
    pdf.write(io)
    io.string
  end

  it 'does nothing when no TSA is configured' do
    pdf = blank_pdf

    expect(described_class.apply(pdf, tsa_url: nil)).to eq([pdf, 'none'])
  end

  it 'fails when a required TSA URL is missing' do
    Qes::Config[:tsa_required] = true
    pdf = blank_pdf

    expect(described_class.apply(pdf, tsa_url: nil)).to eq([pdf, 'failed'])
  end

  it 'rejects a token from a TSA outside the configured trust roots' do
    allow(Qes).to receive(:tsa_trust_roots).and_return(QesHelpers.trust_roots)
    stub_tsa!
    pdf = blank_pdf

    expect(described_class.apply(pdf, tsa_url: 'http://tsa.test')).to eq([pdf, 'failed'])
  end

  it 'rejects an intact token when TSA trust roots are absent' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([])
    stub_tsa!
    pdf = blank_pdf

    expect(described_class.apply(pdf, tsa_url: 'http://tsa.test')).to eq([pdf, 'failed'])
  end

  it 'adds a DocTimeStamp signature in a new revision' do
    pdf = blank_pdf
    stub_tsa!

    result, state = described_class.apply(pdf, tsa_url: 'http://tsa.test')

    expect(state).to eq('applied')
    expect(result.byteslice(0, pdf.bytesize)).to eq(pdf)

    signature = HexaPDF::Document.new(io: StringIO.new(result)).signatures.to_a.last

    expect(signature[:Type]).to eq(:DocTimeStamp)
    expect(signature[:SubFilter]).to eq(:'ETSI.RFC3161')
    data = Qes::TbsDocument.signed_data(StringIO.new(result), signature[:ByteRange].value)
    expect(Qes::TimestampToken.verify(OpenSSL::PKCS7.new(signature[:Contents].to_s), data)).to be true
  end

  it 'returns failed when the TSA is unavailable' do
    pdf = blank_pdf
    allow(Faraday).to receive(:new).and_raise(Faraday::ConnectionFailed.new('TSA down'))

    result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.test')

    expect(state).to eq('failed')
    expect(result).to eq(pdf)
  end

  it 'rejects the fake GeneralizedTime token from the upstream handler' do
    pdf = blank_pdf
    stub_request(:post, 'http://timestamp.test')
      .to_return(status: 200, body: OpenSSL::ASN1::GeneralizedTime.new(Time.now.utc).to_der)

    _result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.test')

    expect(state).to eq('failed')
  end

  it 'rejects a token issued for another document' do
    pdf = blank_pdf
    token = QesHelpers.build_timestamp_token(OpenSSL::Digest.digest('SHA256', 'another document'),
                                             key: QesHelpers.tsa_key, certificate: QesHelpers.tsa_certificate)
    stub_request(:post, 'http://timestamp.test')
      .to_return(status: 200, body: QesHelpers.timestamp_response(token))

    _result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.test')

    expect(state).to eq('failed')
  end
end
