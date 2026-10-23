# frozen_string_literal: true

require 'rails_helper'

# Ověření PDF (docs/16): stateless `POST /api/qes/verify` a explicitní
# uložení do složky „Verified documents“ přes `POST /api/qes/verified_documents`.
RSpec.describe 'QES verification API', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
  end

  let(:account) { create(:account) }
  let(:user) { create(:user, account:) }
  let(:headers) { { 'X-Auth-Token' => user.access_token.token } }
  let(:pdf) { QesHelpers.signed_pdf }

  def upload(path = '/api/qes/verify', data: pdf, content_type: 'application/pdf',
             filename: 'contract.pdf', request_headers: headers)
    file = Rack::Test::UploadedFile.new(StringIO.new(data), content_type,
                                       original_filename: filename)

    post path, params: { file: }, headers: request_headers
  end

  describe 'POST /api/qes/verify' do
    it 'returns a valid report for a signed PDF' do
      upload

      expect(response).to have_http_status(:ok)

      body = response.parsed_body

      expect(body['verdict']).to eq('valid')
      expect(body['intact']).to be true
      expect(body['trusted']).to be true
      expect(body['modified']).to be false
      expect(body['level']).to eq('ades')
      expect(body['coverage']).to eq('full')
      expect(body['origin']).to eq('external')
      expect(body['revocation']).to eq('not_checked')
      expect(body['stored']).to be false
      expect(body['signatures'].size).to eq(1)
      expect(body['signatures'].first).to include('kind' => 'qes', 'level' => 'ades',
                                                 'intact' => true, 'trusted' => true)
      expect(body['file']['name']).to eq('contract.pdf')
      expect(body['file']['sha256']).to eq(Digest::SHA256.hexdigest(pdf))
    end

    it 'returns valid_untrusted for a self-signed certificate' do
      upload(data: QesHelpers.signed_pdf(pkcs: QesHelpers.self_signed_pkcs12))

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['verdict']).to eq('valid_untrusted')
      expect(response.parsed_body['intact']).to be true
      expect(response.parsed_body['trusted']).to be false
    end

    it 'returns invalid for a tampered PDF' do
      tampered = pdf.dup
      tampered[-1] = tampered[-1] == 'x' ? 'y' : 'x'

      upload(data: tampered)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['verdict']).to eq('invalid')
      expect(response.parsed_body['intact']).to be false
    end

    it 'returns invalid and modified for an appended PDF' do
      upload(data: "#{pdf}\n% appended\n")

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['verdict']).to eq('invalid')
      expect(response.parsed_body['modified']).to be true
    end

    it 'returns unsigned for a PDF without signatures' do
      upload(data: QesHelpers::TEST_DIR.join('fixtures', 'input.pdf').binread)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['verdict']).to eq('unsigned')
      expect(response.parsed_body['signatures']).to eq([])
    end

    it 'returns docuseal origin for a PDF from this account' do
      submitter = QesHelpers.build_qes_submitter(account:)
      signed = QesHelpers.signed_pdf(submitter:)

      CompletedDocument.create!(
        sha256: Base64.urlsafe_encode64(Digest::SHA256.digest(signed)),
        submitter:
      )

      upload(data: signed)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['origin']).to eq('docuseal')
    end

    it 'does not store the PDF' do
      pdf # podepsané PDF vytvoří template submittera ještě před měřením

      expect do
        upload
      end.not_to change { [account.templates.count, ActiveStorage::Attachment.count] }
    end

    it 'rejects a PDF that is not a PDF' do
      upload(data: 'not a pdf')

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('invalid_pdf')
    end

    it 'rejects a PDF with a wrong content type' do
      upload(content_type: 'application/octet-stream')

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('invalid_pdf')
    end

    it 'rejects a PDF that is too large' do
      Qes::Config[:pdf_max_bytes] = 10

      upload

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('file_too_large')
    end

    it 'rejects an encrypted PDF' do
      encrypted = HexaPDF::Document.new
      encrypted.pages.add
      encrypted.encrypt(algorithm: :aes, key_length: 256, user_password: 'secret')
      io = StringIO.new
      encrypted.write(io)

      upload(data: io.string)

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('encrypted_pdf')
    end

    it 'requires an API token' do
      upload(request_headers: {})

      expect(response).to have_http_status(:unauthorized)
    end

    it 'is disabled when QES is not enabled' do
      Qes::Config[:enabled] = false

      upload

      expect(response).to have_http_status(:not_found)
    end
  end

  describe 'POST /api/qes/verified_documents' do
    it 'stores a valid PDF in the Verified documents folder' do
      expect do
        upload('/api/qes/verified_documents')
      end.to change { account.templates.count }.by(1)

      expect(response).to have_http_status(:ok)

      body = response.parsed_body
      template = account.templates.find(body['template_id'])

      expect(body['stored']).to be true
      expect(body['folder']).to eq('Verified documents')
      expect(template.folder_name).to eq('Verified documents')
      expect(template.documents.size).to eq(1)
      expect(template.preferences.dig('qes_verification', 'verdict')).to eq('valid')
      expect(template.preferences.dig('qes_verification', 'stored_at')).to be_present
    end

    it 'does not store an invalid PDF' do
      tampered = pdf.dup
      tampered[-1] = tampered[-1] == 'x' ? 'y' : 'x'

      expect do
        upload('/api/qes/verified_documents', data: tampered)
      end.not_to change { account.templates.count }

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('not_verifiable')
    end
  end

  describe 'verified documents web UI' do
    let(:report) do
      {
        'verdict' => 'valid',
        'intact' => true,
        'trusted' => true,
        'modified' => false,
        'level' => 'ades',
        'coverage' => 'full',
        'origin' => 'docuseal',
        'revocation' => 'not_checked',
        'seal' => { 'present' => true, 'trusted' => true, 'count' => 1 },
        'signatures' => [
          {
            'kind' => 'qes',
            'level' => 'ades',
            'intact' => true,
            'trusted' => true,
            'coverage' => 'full',
            'common_name' => 'Jan Novák',
            'subject' => 'CN=Jan Novák, O=Firma s.r.o., C=CZ',
            'issuer' => 'CN=PostSignum Qualified CA 4, O=PostSignum, C=CZ',
            'serial' => '0x1A2B3C',
            'signing_time' => '2026-10-22T09:15:00Z',
            'not_before' => '2025-01-01T00:00:00Z',
            'not_after' => '2027-01-01T00:00:00Z',
            'chain' => ['CN=Jan Novák', 'CN=PostSignum Qualified CA 4']
          }
        ],
        'trusted_roots' => ['CN=PostSignum Root QCA 4, O=PostSignum, C=CZ'],
        'messages' => [{ 'status' => 'success', 'text' => 'Signature valid' }],
        'validated_at' => '2026-10-22T09:16:00Z',
        'file' => { 'name' => 'smlouva.pdf', 'size' => 123_456, 'sha256' => 'abc123' },
        'stored_at' => '2026-10-22T09:17:00Z'
      }
    end

    let!(:template) do
      create(:template, account:, author: user,
                        preferences: { 'qes_verification' => report })
    end

    before do
      sign_in(user)
    end

    it 'renders the verification report and PDF actions' do
      get template_path(template)

      expect(response).to have_http_status(:ok)
      expect(response.body).to include('PDF verification')
      expect(response.body).to include('Signature is valid')
      expect(response.body).to include('Jan Novák')
      expect(response.body).to include('Download PDF')
      expect(response.body).to include('Preview PDF')
    end

    it 'renders the PDF preview in a modal' do
      get template_qes_verification_path(template), headers: { 'Turbo-Frame' => 'modal' }

      expect(response).to have_http_status(:ok)
      expect(response.body).to include('<iframe')
      expect(response.body).to include('src=')
    end

    it 'downloads the stored PDF as an attachment' do
      get template_path(template)

      href = Nokogiri::HTML(response.body).at_css('#qes_verification_download')[:href]

      get href

      expect(response).to have_http_status(:ok)
      expect(response.headers['Content-Disposition']).to include('attachment')
    end

    it 'does not render the report for a regular template' do
      regular_template = create(:template, account:, author: user)

      get template_path(regular_template)

      expect(response.body).not_to include('PDF verification')
    end
  end
end
