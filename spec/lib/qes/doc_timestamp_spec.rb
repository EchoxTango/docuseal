# frozen_string_literal: true

require 'rails_helper'

# Dokumentový timestamp (PAdES-LTA, SPEC § 7.6): nová inkrementální revize
# s `DocTimeStamp`/`ETSI.RFC3161`; kryje DSS i pečeť.
RSpec.describe Qes::DocTimestamp do
  before { QesHelpers.configure! }

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
    allow_any_instance_of(Submissions::TimestampHandler).to receive(:sign) do |_handler, io, byte_range|
      QesHelpers.timestamp_token(io, byte_range)
    end
    pdf = blank_pdf

    expect(described_class.apply(pdf, tsa_url: 'http://tsa.test')).to eq([pdf, 'failed'])
  end

  it 'adds a DocTimeStamp signature in a new revision' do
    pdf = blank_pdf
    token = File.binread(QesHelpers::TEST_DIR.join('fixtures', 'digicert-token.der'))
    allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign).and_return(token)

    result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.digicert.com')

    expect(state).to eq('applied')
    expect(result.byteslice(0, pdf.bytesize)).to eq(pdf)

    signature = HexaPDF::Document.new(io: StringIO.new(result)).signatures.to_a.last

    expect(signature[:Type]).to eq(:DocTimeStamp)
    expect(signature[:SubFilter]).to eq(:'ETSI.RFC3161')
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
    allow_any_instance_of(Submissions::TimestampHandler).to receive(:sign) do
      OpenSSL::ASN1::GeneralizedTime.new(Time.now.utc).to_der
    end

    _result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.test')

    expect(state).to eq('failed')
  end

  it 'rejects a token issued for another document' do
    pdf = blank_pdf
    token = File.binread(QesHelpers::TEST_DIR.join('fixtures', 'digicert-token.der'))
    response = instance_double(Faraday::Response, status: 200, body: token)
    connection = instance_double(Faraday::Connection, post: response)
    allow(Faraday).to receive(:new).and_return(connection)

    _result, state = described_class.apply(pdf, tsa_url: 'http://timestamp.test')

    expect(state).to eq('failed')
  end
end
