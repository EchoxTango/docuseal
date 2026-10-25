# frozen_string_literal: true

require 'rails_helper'

# Kontrakty upstream souborů, na které fork nasedá (SPEC § 14, docs/18 § 2.2).
# Cílem je, aby rebase, který změní signaturu/metodu/struct, spadl tady místo
# až na stagingu (M19).
RSpec.describe 'Upstream contracts used by the QES fork' do
  before { QesHelpers.configure! }

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:field) { submitter.submission.template_fields.find { |f| f['type'] == 'qes' } }
  let(:pkcs) { QesHelpers.pkcs12 }

  describe 'lib/verify_pdf_signature.rb' do
    it 'keeps SignatureStruct and MessageStruct members' do
      expect(VerifyPdfSignature::SignatureStruct.members).to include(
        :messages, :reason, :signing_time, :common_name, :type, :verified, :trusted, :modified
      )
      expect(VerifyPdfSignature::MessageStruct.members).to include(:text, :status)
    end

    it 'returns verified/trusted/modified per signature' do
      pdf = QesHelpers.signed_pdf
      signature = VerifyPdfSignature.call(StringIO.new(pdf), []).first

      expect(signature).to have_attributes(verified: true, trusted: true, modified: false)
      expect(signature.messages.map(&:text)).to include(I18n.t('signed_with_trusted_certificate'))

      allow(Qes).to receive(:trust_roots).and_return([])
      signature = VerifyPdfSignature.call(StringIO.new(pdf), []).first

      expect(signature.type).to eq('ETSI.CAdES.detached')
      expect(signature.verified).to be true
      expect(signature.trusted).to be false
      expect(signature.modified).to be false
      expect(signature.messages.map(&:status)).to include(:success, :error)
    end

    it 'exposes crypto helpers used by Qes::Validator' do
      pdf = QesHelpers.signed_pdf
      byte_range = Qes::TbsDocument.byte_range(pdf)
      contents = HexaPDF::Document.new(io: StringIO.new(pdf)).signatures.to_a.first[:Contents].to_s
      pkcs7 = OpenSSL::PKCS7.new(contents)
      data = VerifyPdfSignature.signed_data(StringIO.new(pdf), byte_range)

      expect(VerifyPdfSignature.verify_contents(pkcs7, data, [])).to be true
      expect(VerifyPdfSignature.signer_certificate(pkcs7)).to be_present
    end
  end

  describe 'lib/submissions/generate_result_attachments.rb' do
    it 'returns the pdfs index from generate_pdfs with a base' do
      base = HexaPDF::Document.new(io: StringIO.new(QesHelpers.signed_pdf))
      pdfs = Submissions::GenerateResultAttachments.generate_pdfs(submitter, base:, page_offsets: {})

      expect(pdfs).to be_a(Hash)
      expect(pdfs.values).to all(be_a(HexaPDF::Document))
    end

    it 'builds signing params for the seal' do
      params = Submissions::GenerateResultAttachments.build_signing_params(submitter, pkcs, nil)

      expect(params.keys).to contain_exactly(:certificate, :key, :certificate_chain)
    end

    it 'keeps single_sign_reason working before the submitter completes' do
      expect(Submissions::GenerateResultAttachments.single_sign_reason(submitter)).to be_present
    end
  end

  describe 'lib/submissions/generate_combined_attachment.rb' do
    it 'returns a HexaPDF document from build_combined_pdf' do
      pdf = Submissions::GenerateCombinedAttachment.build_combined_pdf(submitter, with_audit: false)

      expect(pdf).to be_a(HexaPDF::Document)
      expect(pdf.pages.count).to be_positive
    end

    it 'builds the combined document when template_schema is nil (API submission)' do
      submitter.submission.update!(template_schema: nil)

      pdf = Submissions::GenerateCombinedAttachment.build_combined_pdf(submitter, with_audit: false)

      expect(pdf.pages.count).to be_positive
    end
  end

  describe 'lib/submissions/timestamp_handler.rb' do
    it 'creates a DocTimeStamp field' do
      signature = Struct.new(:document, :values) do
        def [](key) = values[key]

        def []=(key, value)
          values[key] = value
        end
      end.new(Struct.new(:version).new, {})

      Submissions::TimestampHandler.new(tsa_url: 'http://tsa.test').finalize_objects(nil, signature)

      expect(signature[:Type]).to eq(:DocTimeStamp)
      expect(signature[:SubFilter]).to eq(:'ETSI.RFC3161')
    end
  end

  describe 'lib/submitters/submit_values.rb' do
    it 'calls Qes::ValueValidator from validate_values!' do
      allow(Qes::ValueValidator).to receive(:call)

      Submitters::SubmitValues.send(:validate_values!, {}, submitter, {}, nil)

      expect(Qes::ValueValidator).to have_received(:call).with({}, submitter)
    end
  end

  describe 'lib/submissions/generate_audit_trail.rb' do
    it 'appends the QES audit page for a completed session' do
      create(:qes_session, submitter:, submission: submitter.submission, account: submitter.account,
                            field_uuid: field['uuid'], state: 'completed', completed_at: Time.current,
                            certificate_info: { 'subject' => 'CN=Jan Novák', 'issuer' => 'CN=Test Root',
                                                'serial' => '0x1001' },
                            validation_report: { 'intact' => true, 'trusted' => true,
                                                 'coverage' => 'full' })
      submitter.update!(completed_at: Time.current)
      submitter.submission.update!(completed_at: Time.current)

      document = Submissions::GenerateAuditTrail.build_audit_trail(submitter.submission)
      io = StringIO.new
      document.write(io, validate: false)
      text = Pdfium::Document.open_io(StringIO.new(io.string)) do |pdf|
        (0...pdf.page_count).map { |index| pdf.get_page(index).text }.join("\n")
      end

      expect(text).to include(I18n.t('qes.audit.title'))
    end
  end

  describe 'QES model hooks' do
    it 'keeps the strict signing order for a template with a qes field' do
      expect(submitter.submission.submitters_order_preserved?).to be true
    end

    it 'includes qes in with_signature_fields?' do
      expect(submitter.with_signature_fields?).to be true
    end
  end

  describe 'routes' do
    it 'keeps the QES routes the app uses' do
      routes = Rails.application.routes

      expect(routes.recognize_path('/qes/sessions/token', method: :get)).to include(
        controller: 'qes/sessions', action: 'show', token: 'token'
      )
      expect(routes.recognize_path('/qes/sessions/token/certificate', method: :post)).to include(
        controller: 'qes/sessions', action: 'certificate'
      )
      expect(routes.recognize_path('/qes/sign', method: :get)).to include(controller: 'qes/app')
      expect(routes.recognize_path('/.well-known/assetlinks.json', method: :get)).to include(
        controller: 'qes/well_known'
      )
      expect(routes.recognize_path('/api/qes/verify', method: :post)).to include(
        controller: 'api/qes_verifications', action: 'create'
      )
      expect(routes.recognize_path('/s/slug/qes_sessions', method: :post)).to include(
        controller: 'qes/form_sessions', action: 'create'
      )
    end
  end
end
