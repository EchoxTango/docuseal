# frozen_string_literal: true

require 'rails_helper'

# Ověření PDF (docs/16): report nad libovolným PDF, QES trust roots,
# pečeť DocuSealu a informativní `origin`.
RSpec.describe Qes::Verifier do
  before { QesHelpers.configure! }

  let(:pdf) { QesHelpers.signed_pdf }

  def modify_page(bytes)
    document = HexaPDF::Document.new(io: StringIO.new(bytes))
    document.pages[0].canvas(type: :overlay).rectangle(40, 40, 100, 100).fill
    output = StringIO.new
    document.write(output, incremental: true)

    output.string
  end

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

  it 'keeps a DSS/LTV update valid' do
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    with_dss = Qes::Dss.apply(pdf, crls: [crl.to_der])

    report = described_class.call(with_dss, name: 'with-dss.pdf')

    expect(report[:verdict]).to eq('valid')
    expect(report[:coverage]).to eq('partial')
    expect(report[:modified]).to be false
    validation = Qes::Validator.call(with_dss, trust_roots: QesHelpers.trust_roots)
    expect(validation).to include(ok: true, coverage_valid: true)
    signature = Qes::Validator.signature_dicts(with_dss).last
    range = signature[:ByteRange].value
    revision = with_dss.byteslice(0, range[2] + range[3])
    expect(Qes::Validator.coverage(revision, signature)).to eq('full')

    changed = described_class.call(modify_page(with_dss), name: 'changed-after-dss.pdf')
    expect(changed).to include(verdict: 'invalid', modified: true)
  end

  it 'keeps a DSS and DocTS (PAdES-LTA) update valid' do
    submitter = QesHelpers.build_qes_submitter
    allow(Accounts).to receive(:load_trusted_certs).with(submitter.account)
      .and_return([QesHelpers.pkcs12.certificate])
    sealed = QesHelpers.signed_pdf(seal: true, submitter:)
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    with_dss = Qes::Dss.apply(sealed, crls: [crl.to_der],
                              signature_contents: QesHelpers.signature_contents(sealed))

    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!

    lta, state = Qes::DocTimestamp.apply(with_dss, tsa_url: 'http://tsa.test')

    expect(state).to eq('applied')

    report = described_class.call(lta, name: 'lta.pdf', account: submitter.account)

    expect(report[:modified]).to be false
    expect(report[:verdict]).to eq('valid')
    expect(report[:signatures].map { |signature| signature[:kind] })
      .to include('qes', 'seal', 'timestamp')
    expect(report[:signatures].last[:tsa_trusted]).to be true

    allow(Qes).to receive(:tsa_trust_roots).and_return([])
    untrusted = described_class.call(lta, name: 'lta.pdf', account: submitter.account)
    expect(untrusted[:verdict]).to eq('invalid')
    expect(untrusted[:modified]).to be true
    expect(untrusted[:signatures].last).to include(intact: true, tsa_trusted: false)
  end

  it 'rejects an untrusted seal even when a later DocTS covers it' do
    submitter = QesHelpers.build_qes_submitter
    sealed, state = Qes::Seal.apply(pdf, submitter.account, submitter:,
                                    pkcs: QesHelpers.self_signed_pkcs12)
    expect(state).to eq('applied')
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    stamped, state = Qes::DocTimestamp.apply(sealed, tsa_url: 'http://tsa.test')

    expect(state).to eq('applied')
    report = described_class.call(stamped, name: 'untrusted-seal.pdf')

    expect(report[:modified]).to be true
    expect(report[:verdict]).to eq('invalid')
  end

  [false, true].each do |roots_configured|
    it "detects modified content followed by a self-made DocTS (TSA roots configured=#{roots_configured})" do
      if roots_configured
        allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
      end
      changed = modify_page(pdf)
      stamped = QesHelpers.append_timestamp(changed, certificate: QesHelpers.self_signed_tsa_certificate)

      report = described_class.call(stamped, name: 'changed-and-timestamped.pdf')

      expect(report[:inspection]).to eq('complete')
      expect(report[:intact]).to be true
      expect(report[:modified]).to be true
      expect(report[:verdict]).to eq('invalid')
      expect(report[:signatures].last).to include(intact: true, tsa_trusted: false)

      # Totéž musí platit pro výchozí cestu bez trusted_ranges z validátoru.
      signatures = VerifyPdfSignature.call(StringIO.new(stamped), [])
      expect(signatures.map(&:verified)).to all(be true)
      expect(signatures.first.modified).to be true
      expect(signatures.last.tsa_trusted).to be false
    end
  end

  it 'rejects content changes even when a trusted DocTS covers them' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    stamped, state = Qes::DocTimestamp.apply(modify_page(pdf), tsa_url: 'http://tsa.test')
    expect(state).to eq('applied')

    report = described_class.call(stamped, name: 'changed-with-trusted-timestamp.pdf')
    expect(report).to include(intact: true, modified: true, verdict: 'invalid', inspection: 'complete')
    expect(report[:signatures].last).to include(intact: true, tsa_trusted: true)
    expect(Qes::Validator.call(stamped, trust_roots: QesHelpers.trust_roots))
      .to include(ok: false, modified: true)
    expect(VerifyPdfSignature.call(StringIO.new(stamped), []).any?(&:modified)).to be true
  end

  it 'accepts QES followed only by DSS and trusted DocTS, without a seal' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    with_dss = Qes::Dss.apply(pdf, certs: [QesHelpers.certificate.to_der],
                                  signature_contents: QesHelpers.signature_contents(pdf))
    stamped, state = Qes::DocTimestamp.apply(with_dss, tsa_url: 'http://tsa.test')
    expect(state).to eq('applied')
    expect(described_class.call(stamped, name: 'lt-with-timestamp.pdf'))
      .to include(verdict: 'valid', modified: false)
    expect(Qes::Validator.call(stamped, trust_roots: QesHelpers.trust_roots)[:ok]).to be true
    expect(VerifyPdfSignature.call(StringIO.new(stamped), []).any?(&:modified)).to be false
  end

  it 'keeps repeated trusted DocTS and trailing DSS updates valid' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    stamped = pdf
    2.times do
      stamped, state = Qes::DocTimestamp.apply(stamped, tsa_url: 'http://tsa.test')
      expect(state).to eq('applied')
    end
    stamped = Qes::Dss.apply(stamped, certs: [QesHelpers.certificate.to_der])

    expect(described_class.call(stamped, name: 'renewed-lta.pdf'))
      .to include(verdict: 'valid', modified: false, coverage: 'partial')
    expect(Qes::Validator.call(stamped, trust_roots: QesHelpers.trust_roots)[:ok]).to be true
  end

  it 'does not let a new widget borrow a previously trusted timestamp' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    stamped, state = Qes::DocTimestamp.apply(pdf, tsa_url: 'http://tsa.test')
    expect(state).to eq('applied')
    document = HexaPDF::Document.new(io: StringIO.new(stamped))
    signature = document.signatures.to_a.last
    forged = document.add({ FT: :Sig, V: signature, T: 'Borrowed timestamp', Type: :Annot,
                          Subtype: :Widget, Rect: [10, 10, 80, 80], P: document.pages[0] })
    document.acro_form[:Fields] << forged
    document.pages[0][:Annots] ||= []
    document.pages[0][:Annots] << forged
    output = StringIO.new
    document.write(output, incremental: true, validate: false)

    expect(described_class.call(output.string, name: 'borrowed-timestamp.pdf'))
      .to include(verdict: 'invalid', modified: true)
  end

  %i[page annotation form_value].each do |change|
    it "rejects #{change} changes before a trusted DocTS" do
      document = HexaPDF::Document.new(io: StringIO.new(pdf))
      # Include an ordinary form field in the signed revision for the value test.
      if change == :form_value
        field = document.acro_form.create_text_field('Amount')
        field.field_value = '100'
        pkcs = QesHelpers.pkcs12
        output = StringIO.new
        document.sign(output, certificate: pkcs.certificate, key: pkcs.key,
                              certificate_chain: pkcs.ca_certs, signature_type: :pades,
                              write_options: { validate: false })
        document = HexaPDF::Document.new(io: StringIO.new(output.string))
      end
      case change
      when :page
        document.pages.add
      when :annotation
        document.pages[0][:Annots] ||= []
        document.pages[0][:Annots] << document.add({ Type: :Annot, Subtype: :Text,
                                                  Rect: [10, 10, 80, 80], Contents: 'Changed terms' })
      when :form_value
        document.acro_form.field_by_name('Amount').field_value = '900'
      end
      output = StringIO.new
      document.write(output, incremental: true, validate: false)
      allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
      stub_tsa!
      stamped, state = Qes::DocTimestamp.apply(output.string, tsa_url: 'http://tsa.test')
      expect(state).to eq('applied')
      expect(described_class.call(stamped, name: 'changed.pdf'))
        .to include(verdict: 'invalid', modified: true, intact: true)
    end
  end

  it 'keeps a trusted DocTS valid before modification and detects content appended after it' do
    allow(Qes).to receive(:tsa_trust_roots).and_return([QesHelpers.tsa_root_certificate])
    stub_tsa!
    stamped, state = Qes::DocTimestamp.apply(pdf, tsa_url: 'http://tsa.test')
    expect(state).to eq('applied')

    report = described_class.call(stamped, name: 'trusted-timestamp.pdf')
    expect(report[:verdict]).to eq('valid')
    expect(report[:modified]).to be false
    expect(report[:signatures].last).to include(intact: true, tsa_trusted: true)
    signatures = VerifyPdfSignature.call(StringIO.new(stamped), [])
    expect(signatures.last.tsa_trusted).to be true
    expect(signatures.any?(&:modified)).to be false

    changed = modify_page(stamped)
    report = described_class.call(changed, name: 'modified-after-timestamp.pdf')
    expect(report[:intact]).to be true
    expect(report[:verdict]).to eq('invalid')
    expect(report[:modified]).to be true
    expect(VerifyPdfSignature.call(StringIO.new(changed), []).any?(&:modified)).to be true

    forged = QesHelpers.append_timestamp(changed, certificate: QesHelpers.self_signed_tsa_certificate)
    report = described_class.call(forged, name: 'modified-after-trusted-timestamp-and-forged.pdf')
    expect(report[:intact]).to be true
    expect(report[:verdict]).to eq('invalid')
    expect(report[:modified]).to be true
  end

  it 'marks even an intact untrusted DocTS after an accepted signature as modified' do
    stamped = QesHelpers.append_timestamp(pdf, certificate: QesHelpers.self_signed_tsa_certificate)

    report = described_class.call(stamped, name: 'untrusted-timestamp.pdf')

    expect(report[:intact]).to be true
    expect(report[:modified]).to be true
    expect(report[:verdict]).to eq('invalid')
  end

  it 'returns only valid_untrusted for an intact untrusted timestamp without an accepted boundary' do
    document = HexaPDF::Document.new
    document.pages.add
    output = StringIO.new
    document.write(output)
    stamped = QesHelpers.append_timestamp(output.string, certificate: QesHelpers.self_signed_tsa_certificate)

    report = described_class.call(stamped, name: 'timestamp-only.pdf')

    expect(report[:intact]).to be true
    expect(report[:verdict]).to eq('valid_untrusted')
    expect(report[:signatures].last).to include(tsa_trusted: false, time_source: 'current')
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

  it 'detects an untrusted signature after the last accepted boundary even without page changes' do
    submitter = QesHelpers.build_qes_submitter
    sealed, state = Qes::Seal.apply(pdf, submitter.account, submitter:,
                                    pkcs: QesHelpers.self_signed_pkcs12)
    expect(state).to eq('applied')

    report = described_class.call(sealed, name: 'untrusted-signature.pdf')

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
