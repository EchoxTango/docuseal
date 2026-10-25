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

  it 'preserves and deduplicates both signers evidence and VRI entries' do
    first_pdf = QesHelpers.signed_pdf
    first_contents = QesHelpers.signature_contents(first_pdf)
    first_cert = QesHelpers.certificate.to_der
    first_crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread).to_der
    first_pdf = described_class.apply(first_pdf, certs: [first_cert], crls: [first_crl],
                                                ocsps: ['first OCSP'], signature_contents: first_contents)
    document = HexaPDF::Document.new(io: StringIO.new(first_pdf))
    second_pkcs = QesHelpers.self_signed_pkcs12
    output = StringIO.new
    document.sign(output, certificate: second_pkcs.certificate, key: second_pkcs.key,
                          signature_type: :pades, write_options: { validate: false })
    second_contents = QesHelpers.signature_contents(output.string)
    second_cert = second_pkcs.certificate.to_der
    result = described_class.apply(output.string, certs: [first_cert, second_cert, second_cert],
                                                  crls: [first_crl, first_crl], ocsps: ['second OCSP'],
                                                  signature_contents: second_contents)

    expect(result).to start_with(output.string)
    doc = HexaPDF::Document.new(io: StringIO.new(result))
    dss = doc.catalog[:DSS]
    expect(dss[:Certs].map(&:stream)).to contain_exactly(first_cert, second_cert)
    expect(dss[:CRLs].map(&:stream)).to eq([first_crl])
    expect(dss[:OCSPs].map(&:stream)).to contain_exactly('first OCSP', 'second OCSP')
    first_vri = dss[:VRI][Digest::SHA1.hexdigest(first_contents).upcase.to_sym]
    second_vri = dss[:VRI][Digest::SHA1.hexdigest(second_contents).upcase.to_sym]
    expect(first_vri[:Cert].map(&:stream)).to eq([first_cert])
    expect(first_vri[:CRL].map(&:stream)).to eq([first_crl])
    expect(first_vri[:OCSP].map(&:stream)).to eq(['first OCSP'])
    expect(second_vri[:Cert].map(&:stream)).to contain_exactly(first_cert, second_cert)

    # Opakované doplnění stejného VRI zachová jeho dosavadní důkazy.
    repeated = described_class.apply(result, certs: [second_cert], ocsps: ['second OCSP'],
                                            signature_contents: first_contents)
    dss = HexaPDF::Document.new(io: StringIO.new(repeated)).catalog[:DSS]
    expect(dss[:VRI].value.size).to eq(2)
    expect(dss[:Certs].size).to eq(2)
    first_vri = dss[:VRI][Digest::SHA1.hexdigest(first_contents).upcase.to_sym]
    expect(first_vri[:Cert].map(&:stream)).to contain_exactly(first_cert, second_cert)
    expect(first_vri[:OCSP].map(&:stream)).to contain_exactly('first OCSP', 'second OCSP')
    expect(first_vri[:CRL].map(&:stream)).to eq([first_crl])

    doc.signatures.each do |signature|
      data = Qes::TbsDocument.signed_data(StringIO.new(result), signature[:ByteRange].value)
      expect(VerifyPdfSignature.verify_contents(OpenSSL::PKCS7.new(signature[:Contents]), data, [])).to be true
    end
  end
end
