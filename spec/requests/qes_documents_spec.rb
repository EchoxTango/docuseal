# frozen_string_literal: true

require 'rails_helper'

# Přímý podpis PDF (docs/15 § 5.1): upload PDF přes API token založí šablonu
# ve složce „Direct signing“ s polem `qes`; obřad se pak spouští existujícím
# endpointem `/s/:slug/qes_sessions` (taky s API tokenem).
RSpec.describe 'QES documents API', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
  end

  let(:account) { create(:account) }
  let(:user) { create(:user, account:) }
  let(:headers) { { 'X-Auth-Token' => user.access_token.token } }
  let(:pdf) { QesHelpers::TEST_DIR.join('fixtures', 'input.pdf').binread }

  def upload(data = pdf, content_type: 'application/pdf', filename: 'contract.pdf', request_headers: headers)
    file = Rack::Test::UploadedFile.new(StringIO.new(data), content_type, original_filename: filename)

    post '/api/qes/documents', params: { file: }, headers: request_headers
  end

  describe 'POST /api/qes/documents' do
    it 'creates a template with a qes field and page previews' do
      upload

      expect(response).to have_http_status(:created)

      body = response.parsed_body
      template = account.templates.find(body['template_id'])

      expect(template.name).to eq('contract.pdf')
      expect(template.folder_name).to eq('Direct signing')
      expect(template.submitters.size).to eq(1)
      expect(template.fields.size).to eq(1)
      expect(template.fields.first['type']).to eq('qes')
      expect(template.fields.first['preferences']).to eq({ 'level' => 'ades' })
      expect(template.documents.size).to eq(1)

      expect(body['field']).to eq(template.fields.first)
      expect(body['submitter_role']).to eq(template.submitters.first['name'])
      expect(body['stamp']).to eq({ 'width' => Qes::Stamp::MIN_WIDTH,
                                   'height' => Qes::Stamp::MIN_HEIGHT })

      pages = body['document']['pages']

      expect(pages.size).to eq(1)
      expect(pages.first['index']).to eq(0)
      expect(pages.first['width']).to be_within(1).of(595.28)
      expect(pages.first['height']).to be_within(1).of(841.89)
      expect(pages.first['preview_url']).to include('/file/', '0.png')
    end

    it 'stores the requested level and display name' do
      post '/api/qes/documents',
           params: { file: Rack::Test::UploadedFile.new(StringIO.new(pdf), 'application/pdf',
                                                      original_filename: 'contract.pdf'),
                      display_name: 'Jan Novák', level_required: 'qes' },
           headers: headers

      expect(response).to have_http_status(:created)
      template = account.templates.find(response.parsed_body['template_id'])

      expect(template.submitters.first['name']).to eq('Jan Novák')
      expect(template.fields.first['preferences']).to eq({ 'level' => 'qes' })
    end

    it 'requires an API token' do
      upload(request_headers: {})

      expect(response).to have_http_status(:unauthorized)
    end

    it 'rejects a file that is not a PDF' do
      upload('not a pdf')

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

      upload(io.string)

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('encrypted_pdf')
    end

    it 'rejects an already signed PDF' do
      signed = Qes::TbsDocument.sign(HexaPDF::Document.new.tap { |doc| doc.pages.add })

      upload(signed)

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('already_signed')
    end

    it 'rejects an unsupported level' do
      upload

      post '/api/qes/documents',
           params: { file: Rack::Test::UploadedFile.new(StringIO.new(pdf), 'application/pdf',
                                                       original_filename: 'contract.pdf'),
                      level_required: 'something' },
           headers: headers

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body['error']).to eq('invalid_level')
    end

    it 'is disabled when QES is not enabled' do
      Qes::Config[:enabled] = false

      upload

      expect(response).to have_http_status(:not_found)
    end
  end

  describe 'POST /s/:slug/qes_sessions with an API token' do
    it 'starts the ceremony for the uploaded document' do
      upload

      body = response.parsed_body
      template = account.templates.find(body['template_id'])
      field = template.fields.first

      post "/api/templates/#{template.id}/submissions",
           params: { send_email: false,
                     submitters: [{ role: template.submitters.first['name'],
                                    name: 'Jan Novák', email: user.email }] },
           headers: headers, as: :json

      expect(response).to have_http_status(:ok)

      submitter = template.submissions.order(:id).last.submitters.first

      post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: field['uuid'] }, headers: headers

      expect(response).to have_http_status(:created)
      expect(response.parsed_body['token']).to match(/\A[A-Za-z0-9_-]{43}\z/)
      expect(Qes::Token.find(response.parsed_body['token'])).to be_present
    end

    it 'starts the ceremony without a browser session (slug is the capability)' do
      upload

      template = account.templates.find(response.parsed_body['template_id'])
      field = template.fields.first

      post "/api/templates/#{template.id}/submissions",
           params: { send_email: false,
                     submitters: [{ role: template.submitters.first['name'],
                                    name: 'Jan Novák', email: user.email }] },
           headers: headers, as: :json

      submitter = template.submissions.order(:id).last.submitters.first

      post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: field['uuid'] }

      expect(response).to have_http_status(:created)
      expect(response.parsed_body['token']).to be_present
    end
  end
end
