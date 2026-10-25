# frozen_string_literal: true

require 'rails_helper'

# Ověření PDF (docs/16): report nad libovolným PDF, QES trust roots,
# pečeť DocuSealu a informativní `origin`.
RSpec.describe Qes::Verifier do
  before { QesHelpers.configure! }

  let(:pdf) { QesHelpers.signed_pdf }

  it 'returns a valid report for an AdES signature' do
    report = described_class.call(pdf, name: 'contract.pdf')

    expect(report[:verdict]).to eq('valid')
    expect(report[:intact]).to be true
    expect(report[:trusted]).to be true
    expect(report[:modified]).to be false
    expect(report[:level]).to eq('ades')
    expect(report[:coverage]).to eq('full')
    expect(report[:origin]).to eq('external')
    expect(report[:revocation]).to eq('not_checked')
    expect(report[:signatures].size).to eq(1)
    expect(report[:signatures].first).to include(kind: 'qes', level: 'ades', intact: true,
                                                trusted: true)
    expect(report[:signatures].first[:common_name]).to be_present
    expect(report[:signatures].first[:issuer]).to be_present
    expect(report[:signatures].first[:chain]).to be_present
    expect(report[:file][:sha256]).to eq(Digest::SHA256.hexdigest(pdf))
  end

  it 'returns an indeterminate inspection and invalid verdict on parser failure' do
    signed = pdf
    allow(VerifyPdfSignature).to receive(:call).and_raise(StandardError, 'parser failed')

    report = described_class.call(signed, name: 'parser-failure.pdf')

    expect(report[:inspection]).to eq('indeterminate')
    expect(report[:verdict]).to eq('invalid')
    expect(Qes::Validator.call(signed, trust_roots: QesHelpers.trust_roots)[:ok]).to be false
  end

  it 'returns indeterminate when parsers disagree about the signatures' do
    signed = pdf
    allow(VerifyPdfSignature).to receive(:call).and_return([])

    report = described_class.call(signed, name: 'parser-disagreement.pdf')

    expect(report[:inspection]).to eq('indeterminate')
    expect(report[:verdict]).to eq('invalid')
  end

  it 'does not accept partial coverage even when the secondary parser reports no changes' do
    signature = { kind: 'qes', intact: true, trusted: true, coverage: 'partial' }

    expect(described_class.compute_verdict([signature], [signature], false)).to eq('invalid')
  end

  it 'recognizes a QES certificate' do
    report = described_class.call(QesHelpers.signed_pdf(pkcs: QesHelpers.pkcs12('signer-qscd.p12')),
                                 name: 'qes.pdf')

    expect(report[:verdict]).to eq('valid')
    expect(report[:level]).to eq('qes')
  end

  it 'marks an untrusted certificate as valid_untrusted' do
    report = described_class.call(QesHelpers.signed_pdf(pkcs: QesHelpers.self_signed_pkcs12),
                                 name: 'self-signed.pdf')

    expect(report[:verdict]).to eq('valid_untrusted')
    expect(report[:intact]).to be true
    expect(report[:trusted]).to be false
  end

  it 'does not trust a root that is only in the PDF chain' do
    Qes::Config[:trust_roots] = nil

    report = described_class.call(pdf, name: 'chain-only-root.pdf')

    expect(report[:intact]).to be true
    expect(report[:trusted]).to be false
    expect(report[:verdict]).to eq('valid_untrusted')
  end

  it 'marks a tampered document as invalid' do
    tampered = pdf.dup
    tampered[-1] = tampered[-1] == 'x' ? 'y' : 'x'

    report = described_class.call(tampered, name: 'tampered.pdf')

    expect(report[:verdict]).to eq('invalid')
    expect(report[:intact]).to be false
  end

  it 'marks an appended document as invalid and modified' do
    report = described_class.call("#{pdf}\n% appended\n", name: 'appended.pdf')

    expect(report[:verdict]).to eq('invalid')
    expect(report[:modified]).to be true
  end

  it 'requires a covering signature after a DSS/LTV update' do
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    with_dss = Qes::Dss.apply(pdf, crls: [crl.to_der])

    report = described_class.call(with_dss, name: 'with-dss.pdf')

    expect(report[:verdict]).to eq('invalid')
    expect(report[:coverage]).to eq('partial')
    expect(report[:modified]).to be false
  end

  it 'keeps a DSS and DocTS (PAdES-LTA) update valid' do
    submitter = QesHelpers.build_qes_submitter
    allow(Accounts).to receive(:load_trusted_certs).with(submitter.account)
      .and_return([QesHelpers.pkcs12.certificate])
    sealed = QesHelpers.signed_pdf(seal: true, submitter:)
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    with_dss = Qes::Dss.apply(sealed, crls: [crl.to_der],
                              signature_contents: QesHelpers.signature_contents(sealed))

    allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign) do |_handler, io, byte_range|
      QesHelpers.timestamp_token(io, byte_range)
    end

    lta, state = Qes::DocTimestamp.apply(with_dss, tsa_url: 'http://tsa.test')

    expect(state).to eq('applied')

    report = described_class.call(lta, name: 'lta.pdf', account: submitter.account)

    expect(report[:modified]).to be false
    expect(report[:verdict]).to eq('valid')
    expect(report[:signatures].map { |signature| signature[:kind] })
      .to include('qes', 'seal', 'timestamp')
  end

  it 'rejects an untrusted seal even when a later DocTS covers it' do
    submitter = QesHelpers.build_qes_submitter
    sealed, state = Qes::Seal.apply(pdf, submitter.account, submitter:,
                                    pkcs: QesHelpers.self_signed_pkcs12)
    expect(state).to eq('applied')
    allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign) do |_handler, io, byte_range|
      QesHelpers.timestamp_token(io, byte_range)
    end
    stamped, state = Qes::DocTimestamp.apply(sealed, tsa_url: 'http://tsa.test')

    expect(state).to eq('applied')
    report = described_class.call(stamped, name: 'untrusted-seal.pdf')

    expect(report[:modified]).to be false
    expect(report[:verdict]).to eq('valid_untrusted')
  end

  it 'detects content changes followed by an untrusted seal' do
    document = HexaPDF::Document.new(io: StringIO.new(pdf))
    document.pages[0].canvas(type: :overlay).rectangle(40, 40, 100, 100).fill
    changed = StringIO.new
    document.write(changed, incremental: true)
    submitter = QesHelpers.build_qes_submitter
    sealed, state = Qes::Seal.apply(changed.string, submitter.account, submitter:,
                                    pkcs: QesHelpers.self_signed_pkcs12)

    expect(state).to eq('applied')
    report = described_class.call(sealed, name: 'changed-and-sealed.pdf')

    expect(report[:intact]).to be true
    expect(report[:modified]).to be true
    expect(report[:verdict]).to eq('invalid')
  end

  it 'returns unsigned for a PDF without signatures' do
    unsigned = QesHelpers::TEST_DIR.join('fixtures', 'input.pdf').binread

    report = described_class.call(unsigned, name: 'unsigned.pdf')

    expect(report[:verdict]).to eq('unsigned')
    expect(report[:signatures]).to eq([])
  end

  it 'detects the DocuSeal seal and keeps the app signature intact' do
    submitter = QesHelpers.build_qes_submitter
    allow(Accounts).to receive(:load_trusted_certs).with(submitter.account)
      .and_return([QesHelpers.pkcs12.certificate])
    sealed = QesHelpers.signed_pdf(seal: true, submitter:)

    report = described_class.call(sealed, name: 'sealed.pdf', account: submitter.account)

    expect(report[:verdict]).to eq('valid')
    expect(report[:seal]).to include(present: true, count: 1)
    expect(report[:signatures].size).to eq(2)
    expect(report[:modified]).to be false
  end

  it 'marks a PDF from this DocuSeal account as docuseal' do
    submitter = QesHelpers.build_qes_submitter
    signed = QesHelpers.signed_pdf(submitter:)

    CompletedDocument.create!(
      sha256: Base64.urlsafe_encode64(Digest::SHA256.digest(signed)),
      submitter:
    )

    report = described_class.call(signed, name: 'ours.pdf', account: submitter.account)

    expect(report[:origin]).to eq('docuseal')
  end

  it 'does not mark a PDF from another account as docuseal' do
    submitter = QesHelpers.build_qes_submitter
    signed = QesHelpers.signed_pdf(submitter:)

    CompletedDocument.create!(
      sha256: Base64.urlsafe_encode64(Digest::SHA256.digest(signed)),
      submitter:
    )

    other = FactoryBot.create(:account)
    report = described_class.call(signed, name: 'foreign.pdf', account: other)

    expect(report[:origin]).to eq('external')
  end
end
