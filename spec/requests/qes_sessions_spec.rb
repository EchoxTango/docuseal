# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Qes sessions API', type: :request do
  before do
    QesHelpers.configure!
    stub_memory_cache!
  end

  let(:pkcs) { QesHelpers.pkcs12 }

  def create_qes_session(state: 'awaiting_app', token: nil, expires_at: 10.minutes.from_now, level: 'ades')
    submitter = QesHelpers.build_qes_submitter(level:)
    field = submitter.submission.template_fields.find { |f| f['type'] == 'qes' }

    session = create(:qes_session, submitter:, submission: submitter.submission,
                                    account: submitter.account, field_uuid: field['uuid'],
                                    state: 'created', expires_at:)

    Qes::SessionManager.transition!(session, 'prepared')

    if token
      session.update!(token_digest: Qes::Token.digest(token))
    end

    Qes::SessionManager.transition!(session, 'awaiting_app') if state != 'created'
    session.update!(state:) if state == 'created'
    session.update!(state:) if state == 'failed'

    [session, submitter]
  end


  it 'creates a session for a submission with blank template_fields' do
    submitter = QesHelpers.build_qes_submitter
    submitter.submission.update!(template_fields: nil, template_schema: nil)
    field = submitter.submission.template.fields.find { |f| f['type'] == 'qes' }

    post "/s/#{submitter.slug}/qes_sessions", params: { field_uuid: field['uuid'] }

    expect(response).to have_http_status(:created)
    expect(response.parsed_body['state']).to eq('awaiting_app')
    expect(response.parsed_body['qr_svg']).to include('<svg')
  end

  it 'returns 404 for an unknown token' do
    get '/qes/sessions/unknown'

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body['error']).to eq('unknown_token')
  end

  it 'returns 410 for an expired token' do
    _session, _submitter = create_qes_session(token: 'expired', expires_at: 1.minute.ago)

    get '/qes/sessions/expired'

    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('expired_token')
  end

  it 'returns 410 for a used token' do
    create_qes_session(state: 'failed', token: 'used')

    get '/qes/sessions/used'

    expect(response).to have_http_status(:gone)
    expect(response.parsed_body['error']).to eq('used_token')
  end

  it 'opens the session and returns the payload without data_to_sign' do
    session, submitter = create_qes_session(token: 'open')

    get '/qes/sessions/open'

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('app_opened')
    expect(response.parsed_body['requires_certificate']).to be true
    expect(response.parsed_body).not_to have_key('document_digest')
    expect(response.parsed_body).not_to have_key('data_to_sign')
    expect(session.reload.app_opened_at).to be_present
    expect(response.parsed_body['signer_name']).to eq(submitter.name)
  end

  it 'rejects a certificate chain that is too long' do
    session, _submitter = create_qes_session(token: 'long-chain')
    chain = Array.new(Qes::ControllerConcern::MAX_CHAIN + 1) do
      Base64.strict_encode64(pkcs.ca_certs.first.to_der)
    end

    post '/qes/sessions/long-chain/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain:,
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.state).to eq('awaiting_app')
  end

  it 'rejects an oversized certificate' do
    session, _submitter = create_qes_session(token: 'big-cert')

    post '/qes/sessions/big-cert/certificate', params: {
      certificate: Base64.strict_encode64('x' * (Qes::ControllerConcern::MAX_CERTIFICATE_BYTES + 1)),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.state).to eq('awaiting_app')
  end

  it 'rejects a malformed certificate with 422 instead of 500' do
    session, _submitter = create_qes_session(token: 'malformed')

    post '/qes/sessions/malformed/certificate', params: {
      certificate: Base64.strict_encode64('not a certificate'),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('invalid_certificate')
    expect(session.reload.failure_code).to eq('invalid_certificate')
    expect(session.state).to eq('awaiting_app')
  end

  it 'rejects a certificate that is not qualified' do
    _session, _submitter = create_qes_session(token: 'unqualified')

    post '/qes/sessions/unqualified/certificate', params: {
      certificate: Base64.strict_encode64(QesHelpers.unqualified_certificate.to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('not_qualified')
  end

  it 'rejects a QcSSCD certificate from the phone keystore' do
    _session, _submitter = create_qes_session(token: 'qscd')

    post '/qes/sessions/qscd/certificate', params: {
      certificate: Base64.strict_encode64(QesHelpers.certificate('signer-qscd.crt').to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('level_mismatch')
  end

  it 'requires QcSSCD for a qes field' do
    _session, _submitter = create_qes_session(token: 'qes', level: 'qes')

    post '/qes/sessions/qes/certificate', params: {
      certificate: Base64.strict_encode64(QesHelpers.certificate('signer-ades.crt').to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('qes_required_qscd')
  end

  it 'completes the ceremony end to end over HTTP' do
    session, _submitter = create_qes_session(token: 'sign')

    get '/qes/sessions/sign'
    expect(response).to have_http_status(:ok)

    post '/qes/sessions/sign/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore',
      app: { platform: 'rspec', version: '1.0.0' }
    }

    expect(response).to have_http_status(:ok)
    expect(session.reload.document_digest).to be_present

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/sign/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
    expect(response.parsed_body['level']).to eq('ades')
    expect(session.reload.state).to eq('completed')
    expect(session.signed_document).to be_attached
  end

  it 'stores revocation data in DSS instead of the CMS' do
    session, _submitter = create_qes_session(token: 'big-ltv')
    crl = OpenSSL::X509::CRL.new(QesHelpers.pki_path('root.crl').binread)
    allow(Qes::Ltv).to receive(:fetch_crls).and_return([crl])

    post '/qes/sessions/big-ltv/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:ok)

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/big-ltv/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')

    tbs = HexaPDF::Document.new(io: StringIO.new(session.reload.tbs_document.download))
    reserve = tbs.signatures.to_a.last[:Contents].to_s.bytesize

    expect(reserve).to be < 100_000
    expect(session.reload.final_document).to be_attached

    dss = HexaPDF::Document.new(io: StringIO.new(session.reload.final_document.download)).catalog[:DSS]

    expect(dss[:CRLs].map { |ref| ref.stream.to_s }).to include(crl.to_der)
  end

  it 'returns the signature summary for a completed session' do
    session, _submitter = create_qes_session(token: 'summary')

    get '/qes/sessions/summary'

    post '/qes/sessions/summary/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/summary/complete', params: { signature: Base64.strict_encode64(signature) }

    get "/s/#{session.submitter.slug}/qes_sessions/#{session.id}", headers: { 'Accept' => 'application/json' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['summary_html']).to include("data-qes-summary=\"#{session.id}\"")
    expect(response.parsed_body['summary_html']).to include(pkcs.certificate.subject.to_s)
    # V poli dokumentu je zkrácená varianta (bez issuer/serial a auditu).
    expect(response.parsed_body['summary_html']).to include('bg-base-200/80')
    expect(response.parsed_body['summary_html']).not_to include('Certificate issuer')
  end

  it 'shows the signature summary for a previous signer in the signing form' do
    QesHelpers.with_crl_server do
      submission = QesHelpers.build_qes_submission(count: 2)
      first, second = submission.submitters.order(:id).to_a
      field = Qes.template_fields(submission).find do |f|
        f['submitter_uuid'] == first.uuid && f['type'] == 'qes'
      end
      session = create(:qes_session, submitter: first, submission:, field_uuid: field['uuid'],
                                     account: submission.account)

      Qes::Providers::Mock.new(session, pkcs_path: QesHelpers.pki_path('signer-ades.p12').to_s,
                                        password: 'test').sign!(first, field)
      first.update!(values: first.values.merge(field['uuid'] => session.reload.value_token),
                    completed_at: Time.current)

      get "/s/#{second.slug}"

      expect(response).to have_http_status(:ok)
      expect(response.body).to include("data-qes-summary=\"#{session.id}\"")
      expect(response.body).to include('bg-base-200/80')
    end
  end

  it 'rejects a self-signed QcSSCD certificate that does not chain to a trust root' do
    _session, _submitter = create_qes_session(token: 'selfsigned', level: 'qes')
    _key, cert = QesHelpers.self_signed_qc_sscd_certificate

    post '/qes/sessions/selfsigned/certificate', params: {
      certificate: Base64.strict_encode64(cert.to_der),
      chain: [],
      key_location: 'card'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('not_trusted')
  end

  it 'clears the failure code when a rejected certificate is followed by a valid one' do
    session, _submitter = create_qes_session(token: 'retry-cert')
    _key, bad_cert = QesHelpers.self_signed_qc_sscd_certificate

    post '/qes/sessions/retry-cert/certificate', params: {
      certificate: Base64.strict_encode64(bad_cert.to_der), chain: [], key_location: 'card'
    }

    expect(response).to have_http_status(:unprocessable_content)
    expect(session.reload.failure_code).to eq('not_trusted')

    post '/qes/sessions/retry-cert/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    expect(response).to have_http_status(:ok)
    expect(session.reload.failure_code).to be_nil
  end

  it 'keeps the failure code from the app on abort' do
    session, _submitter = create_qes_session(token: 'abort')

    post '/qes/sessions/abort/abort', params: { code: 'network_error', message: 'offline' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('failed')
    expect(session.reload.failure_code).to eq('network_error')
    expect(session.failure_message).to eq('offline')
  end

  it 'rejects a second complete with a different signature' do
    session, _submitter = create_qes_session(token: 'twice-different')

    get '/qes/sessions/twice-different'

    post '/qes/sessions/twice-different/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice-different/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response.parsed_body['state']).to eq('completed')

    other_key = OpenSSL::PKey::RSA.new(2048)
    other_signature = other_key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice-different/complete', params: { signature: Base64.strict_encode64(other_signature) }

    expect(response).to have_http_status(:conflict)
    expect(response.parsed_body['error']).to eq('wrong_state')
    expect(session.reload.signature).to eq(signature)
  end

  it 'is idempotent when complete is called twice' do
    session, _submitter = create_qes_session(token: 'twice')

    get '/qes/sessions/twice'

    post '/qes/sessions/twice/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: (pkcs.ca_certs || []).map { |cert| Base64.strict_encode64(cert.to_der) },
      key_location: 'phone_keystore'
    }

    data_to_sign = Base64.strict_decode64(response.parsed_body['data_to_sign'])
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), data_to_sign)

    post '/qes/sessions/twice/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response.parsed_body['state']).to eq('completed')

    post '/qes/sessions/twice/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('completed')
    expect(session.reload.state).to eq('completed')
  end

  it 'rejects a foreign signature' do
    session, _submitter = create_qes_session(token: 'foreign')

    get '/qes/sessions/foreign'

    post '/qes/sessions/foreign/certificate', params: {
      certificate: Base64.strict_encode64(pkcs.certificate.to_der),
      chain: [],
      key_location: 'phone_keystore'
    }

    other_key = OpenSSL::PKey::RSA.new(2048)
    signature = other_key.sign(OpenSSL::Digest.new('SHA256'), OpenSSL::Random.random_bytes(16))

    post '/qes/sessions/foreign/complete', params: { signature: Base64.strict_encode64(signature) }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body['error']).to eq('signature_invalid')
    expect(session.reload.state).to eq('failed')
  end

  it 'cancels the session from the app' do
    session, _submitter = create_qes_session(token: 'abort')

    post '/qes/sessions/abort/abort', params: { code: 'user_cancelled' }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['state']).to eq('cancelled')
    expect(session.reload.state).to eq('cancelled')
  end

  it 'rate limits after too many failed token attempts' do
    11.times { get '/qes/sessions/unknown' }

    expect(response).to have_http_status(:too_many_requests)
    expect(response.parsed_body['error']).to eq('rate_limited')
  end
end
