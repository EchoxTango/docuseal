# frozen_string_literal: true

require 'rails_helper'

# DSS slovník (PAdES-LT, SPEC § 7.4): revokační data musí být v PDF, aby je
# validátor (pyHanko/Adobe) našel i bez sítě. Přidává se inkrementálně.
RSpec.describe Qes::Dss do
  before { QesHelpers.configure! }

  def blank_pdf
    pdf = HexaPDF::Document.new
    pdf.pages.add
    io = StringIO.new
    pdf.write(io)
    io.string
  end

  it 'adds a /DSS dictionary with CRLs as an incremental revision' do
    QesHelpers.with_crl_server do
      crls = Qes::Ltv.collect_revocation_data(QesHelpers.certificate, chain: QesHelpers.chain)
      pdf = blank_pdf
      result = described_class.apply(pdf, crls: crls.map(&:to_der))

      expect(result.byteslice(0, pdf.bytesize)).to eq(pdf)

      doc = HexaPDF::Document.new(io: StringIO.new(result))
      dss = doc.catalog[:DSS]

      expect(dss).to be_present
      expect(dss[:CRLs].size).to eq(crls.size)
      expect(dss[:CRLs].first.stream).to eq(crls.first.to_der)
    end
  end

  it 'adds a VRI entry for the signature contents (Adobe LTV)' do
    QesHelpers.with_crl_server do
      crls = Qes::Ltv.collect_revocation_data(QesHelpers.certificate, chain: QesHelpers.chain)
      contents = Random.bytes(100)
      result = described_class.apply(blank_pdf, crls: crls.map(&:to_der),
                                                 certs: [QesHelpers.certificate.to_der],
                                                 signature_contents: contents)
      dss = HexaPDF::Document.new(io: StringIO.new(result)).catalog[:DSS]
      key = Digest::SHA1.hexdigest(contents).upcase.to_sym

      expect(dss[:VRI][key]).to be_present
      expect(dss[:VRI][key][:CRL].size).to eq(crls.size)
      expect(dss[:VRI][key][:Cert].size).to eq(1)
      # VRI klíč je SHA-1 z raw bajtů, ne z hex řetězce (ETSI/Adobe).
      expect(dss[:VRI][Digest::SHA1.hexdigest(contents.unpack1('H*')).upcase.to_sym]).to be_nil
    end
  end

  it 'keeps the input untouched when no CRLs are available' do
    pdf = blank_pdf

    expect(described_class.apply(pdf, crls: [])).to eq(pdf)
  end
end
