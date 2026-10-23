# frozen_string_literal: true

require 'rails_helper'

# Celý kryptografický řetěz bez appky (SPEC § 7): TBS → podepsané atributy →
# raw signatura → CMS → PAdES → validace → DSS → pečeť → DocTS.
RSpec.describe 'QES cryptographic pipeline' do
  before do
    QesHelpers.configure!
    Qes::Config[:seal_pkcs_path] = QesHelpers.pki_path('signer-ades.p12').to_s
    Qes::Config[:seal_pkcs_password] = 'test'
  end

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:field) { submitter.submission.template_fields.find { |f| f['type'] == 'qes' } }
  let(:pkcs) { QesHelpers.pkcs12 }

  def build_signed_pdf(pkcs: self.pkcs, tsa_url: nil)
    tbs_pdf = Qes::TbsDocument.build(submitter, field)
    byte_range = Qes::TbsDocument.byte_range(tbs_pdf)

    expect(byte_range).to be_present
    expect(byte_range[0]).to eq(0)

    data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), byte_range)

    prepared = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate,
                                      chain: pkcs.ca_certs, signing_time: Time.now.utc)

    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), prepared[:signed_attrs_der])

    Qes::CmsBuilder.verify_signature!(pkcs.certificate, signature, prepared[:signed_attrs_der], 'sha256')

    cms_der = Qes::CmsBuilder.complete(data:, signed_attrs_der: prepared[:signed_attrs_der],
                                         signature:, certificate: pkcs.certificate, chain: pkcs.ca_certs,
                                         tsa_url:)

    [tbs_pdf, Qes::Embed.call(tbs_pdf, cms_der), data]
  end

  it 'creates a TBS PDF with a signature field and full coverage' do
    tbs_pdf = Qes::TbsDocument.build(submitter, field)
    doc = HexaPDF::Document.new(io: StringIO.new(tbs_pdf))

    expect(doc.signatures.to_a.size).to eq(1)
    expect(doc.acro_form.field_by_name('Signature1')).to be_present

    byte_range = Qes::TbsDocument.byte_range(tbs_pdf)

    expect(byte_range[2] + byte_range[3]).to eq(tbs_pdf.bytesize)
  end

  it 'produces signed attributes with signingTime and message-digest' do
    tbs_pdf = Qes::TbsDocument.build(submitter, field)
    byte_range = Qes::TbsDocument.byte_range(tbs_pdf)
    data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), byte_range)

    prepared = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate, chain: pkcs.ca_certs)

    attrs = OpenSSL::ASN1.decode(prepared[:signed_attrs_der])
    oids = attrs.value.map { |attr| attr.value.first.oid }

    expect(oids).to include('1.2.840.113549.1.9.3', '1.2.840.113549.1.9.5',
                            '1.2.840.113549.1.9.4', '1.2.840.113549.1.9.16.2.47')

    message_digest = attrs.value.find { |a| a.value.first.oid == '1.2.840.113549.1.9.4' }
                              .value.last.value.first.value

    expect(message_digest).to eq(OpenSSL::Digest.digest('sha256', data))
  end

  it 'produces byte-identical signed attributes for the same signing time' do
    tbs_pdf = Qes::TbsDocument.build(submitter, field)
    byte_range = Qes::TbsDocument.byte_range(tbs_pdf)
    data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), byte_range)
    signing_time = Time.now.utc

    first = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate, chain: pkcs.ca_certs,
                                     signing_time:)
    second = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate, chain: pkcs.ca_certs,
                                      signing_time:)

    expect(second[:signed_attrs_der]).to eq(first[:signed_attrs_der])
  end

  it 'rejects a signature that does not match the certificate' do
    other_key = OpenSSL::PKey::RSA.new(2048)

    expect do
      Qes::CmsBuilder.verify_signature!(pkcs.certificate, other_key.sign(OpenSSL::Digest.new('SHA256'), 'x'),
                                        'x', 'sha256')
    end.to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:signature_invalid) }
  end

  context 'with a CRL server' do
    it 'embeds LTV revocation values and validates as intact, trusted and fully covered' do
      QesHelpers.with_crl_server do
        _tbs_pdf, signed_pdf, _data = build_signed_pdf

        report = Qes::Validator.call(signed_pdf, trust_roots: QesHelpers.trust_roots)

        expect(report[:intact]).to be true
        expect(report[:trusted]).to be true
        expect(report[:coverage]).to eq('full')
        expect(report[:level]).to eq('ades')
        expect(report[:ok]).to be true
      end
    end

    it 'detects a tampered document' do
      QesHelpers.with_crl_server do
        _tbs_pdf, signed_pdf, _data = build_signed_pdf
        tampered = signed_pdf.dup
        tampered[-1] = tampered[-1] == 'x' ? 'y' : 'x'

        report = Qes::Validator.call(tampered, trust_roots: QesHelpers.trust_roots)

        expect(report[:intact]).to be false
      end
    end

    it 'detects a partial coverage' do
      QesHelpers.with_crl_server do
        _tbs_pdf, signed_pdf, _data = build_signed_pdf
        appended = signed_pdf + "\n% appended\n"

        report = Qes::Validator.call(appended, trust_roots: QesHelpers.trust_roots)

        expect(report[:coverage]).to eq('partial')
      end
    end
  end

  context 'with the QES mock provider' do
    it 'runs the whole ceremony and stores signed and final documents' do
      QesHelpers.with_crl_server do
        session = create(:qes_session, submitter:, submission: submitter.submission,
                                        field_uuid: field['uuid'], account: submitter.account)
        provider = Qes::Providers::Mock.new(session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                                    password: 'test')

        report = provider.sign!(submitter, field)

        expect(report[:intact]).to be true
        expect(report[:trusted]).to be true
        expect(session.reload.state).to eq('completed')
        expect(session.signed_document).to be_attached
        expect(session.final_document).to be_attached
        expect(session.level).to eq('ades')
        expect(session.submitter.values[field['uuid']]).to eq(session.value_token)
      end
    end

    it 'adds an incremental DocuSeal seal and keeps the app signature intact' do
      QesHelpers.with_crl_server do
        session = create(:qes_session, submitter:, submission: submitter.submission,
                                        field_uuid: field['uuid'], account: submitter.account)
        provider = Qes::Providers::Mock.new(session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                                    password: 'test')

        provider.sign!(submitter, field)

        signed_pdf = session.reload.signed_document.download
        final_pdf = session.final_document.download

        expect(session.seal_state).to eq('applied')
        expect(session.signed_pdf_sha256).to eq(Digest::SHA256.hexdigest(signed_pdf))
        expect(session.final_pdf_sha256).to eq(Digest::SHA256.hexdigest(final_pdf))

        expect(Qes::Validator.call(final_pdf, trust_roots: QesHelpers.trust_roots)[:intact]).to be true
        expect(HexaPDF::Document.new(io: StringIO.new(final_pdf)).signatures.to_a.size).to eq(2)
      end
    end
  end
end
