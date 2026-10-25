# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'QES token document endpoint', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
  end

  let(:session) { create(:qes_session, state: 'awaiting_app', token_digest: Qes::Token.digest('document')) }
  let(:pkcs) { QesHelpers.pkcs12 }
  let(:certificate_params) do
    {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }
  end

  %w[sha256 sha384].each do |algorithm|
    it "serves the exact TBS with a matching #{algorithm} ByteRange and CMS messageDigest" do
      session.update!(hash_algorithm: algorithm)
      post '/qes/sessions/document/certificate', params: certificate_params
      expect(response).to have_http_status(:ok)
      payload = response.parsed_body

      get '/qes/sessions/document/document'

      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq('application/pdf')
      expect(response.headers['Cache-Control']).to include('no-store')
      expect(response.headers['X-QES-Protocol']).to eq('1')
      expect(response.headers['Referrer-Policy']).to eq('no-referrer')
      pdf = response.body.b
      expect(pdf).to eq(session.reload.tbs_document.download)
      range = payload.fetch('byte_range')
      expect(range).to eq(Qes::TbsDocument.byte_range(pdf))
      expect(range.first).to eq(0)
      expect(range[2] + range[3]).to eq(pdf.bytesize)
      data = range.each_slice(2).map { |offset, length| pdf.byteslice(offset, length) }.join
      digest = OpenSSL::Digest.digest(algorithm, data)
      expect(payload.fetch('document_digest')).to eq(Digest::SHA256.hexdigest(data))
      expect(session.document_digest).to eq(Digest::SHA256.hexdigest(data))
      attrs = OpenSSL::ASN1.decode(Base64.strict_decode64(payload.fetch('data_to_sign')))
      message_digest = attrs.value.find { |attr| attr.value.first.oid == '1.2.840.113549.1.9.4' }
                            .value.last.value.first.value
      expect(message_digest).to eq(digest)

      post '/qes/sessions/document/certificate', params: certificate_params
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body).to eq(payload)
    end
  end

  it 'returns 404 for an unknown token' do
    get '/qes/sessions/unknown/document'
    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body['error']).to eq('unknown_token')
  end

  it 'returns 410 for an expired token even with a stored TBS' do
    session.tbs_document.attach(io: StringIO.new('%PDF-stored'), filename: 'tbs.pdf',
                                content_type: 'application/pdf')
    session.update!(expires_at: 1.minute.ago, state: 'awaiting_signature')
    get '/qes/sessions/document/document'
    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('expired_token')
  end

  %w[created prepared awaiting_app app_opened signed embedded validated].each do |state|
    it "does not serve a document in #{state}" do
      session.update!(state:)
      get '/qes/sessions/document/document'
      expect(response).to have_http_status(:conflict)
      expect(response.parsed_body['error']).to eq('wrong_state')
    end
  end

  %w[completed failed cancelled declined].each do |state|
    it "does not serve a document in terminal state #{state}" do
      session.update!(state:)
      get '/qes/sessions/document/document'
      expect(response).to have_http_status(:gone)
      expect(response.parsed_body['error']).to eq('used_token')
    end
  end

  it 'rejects an awaiting session without its stored TBS' do
    session.update!(state: 'awaiting_signature')
    get '/qes/sessions/document/document'
    expect(response).to have_http_status(:conflict)
    expect(response.parsed_body['error']).to eq('document_missing')
  end

  it 'uses the token endpoint rate limiter' do
    11.times { get '/qes/sessions/unknown/document' }
    expect(response).to have_http_status(:too_many_requests)
    expect(response.parsed_body['error']).to eq('rate_limited')
  end
end
