# frozen_string_literal: true

require 'pathname'

# Pomocné metody pro QES testy: fixtures z hlavního repa (`test/certs/pki`)
# a lokální HTTP server s CRL (certifikáty mají CRL DP na 127.0.0.1:8765).
module QesHelpers
  TEST_DIR = Pathname.new(ENV['QES_TEST_DIR'] || File.expand_path('../../../test', __dir__))
  CRL_PORT = 8765

  module_function

  def pki_path(*parts)
    TEST_DIR.join('certs', 'pki', *parts)
  end

  def pkcs12(name = 'signer-ades.p12', password = 'test')
    OpenSSL::PKCS12.new(pki_path(name).binread, password)
  end

  def certificate(name = 'signer-ades.crt')
    OpenSSL::X509::Certificate.new(pki_path(name).read)
  end

  # Certifikát bez QCStatements (nekvalifikovaný) z fixtures.
  def unqualified_certificate
    OpenSSL::X509::Certificate.new(TEST_DIR.join('certs', 'signer.cert.pem').read)
  end

  def trust_roots
    [OpenSSL::X509::Certificate.new(pki_path('root.crt').read)]
  end

  def chain(p12 = pkcs12)
    (p12.ca_certs || []).map(&:to_der)
  end

  # Vytvoří submittera se šablonou, která má pole typu `qes` (jeden podepisující).
  def build_qes_submitter(account: nil, level: 'ades')
    build_qes_submission(account:, level:).submitters.order(:id).first
  end

  # Vytvoří submission s N signery; každý má vlastní pole `qes` a striktní
  # pořadí (`submitters_order: preserved`, SPEC § 4.6).
  def build_qes_submission(account: nil, level: 'ades', count: 1, attachment_count: 1,
                           field_types: %w[text], qes_attachment_index: 0,
                           qes_fields_per_submitter: 1)
    account ||= FactoryBot.create(:account)
    user = FactoryBot.create(:user, account:)
    template = FactoryBot.create(:template, account:, author: user, only_field_types: field_types,
                                submitter_count: count, attachment_count:)
    attachment_uuid = template.schema[qes_attachment_index]['attachment_uuid']

    template.preferences = template.preferences.merge('submitters_order' => 'preserved') if count > 1

    template.fields += template.submitters.each_with_index.flat_map do |submitter, index|
      Array.new(qes_fields_per_submitter) do |field_index|
        {
          'uuid' => SecureRandom.uuid,
          'submitter_uuid' => submitter['uuid'],
          'name' => ["QES signature #{index + 1}", (field_index + 1)].compact.join(' '),
          'type' => 'qes',
          'required' => true,
          'preferences' => { 'level' => level },
          'areas' => [
            { 'x' => 0.1, 'y' => 0.8 - (field_index * 0.1), 'w' => 0.3, 'h' => 0.06,
              'attachment_uuid' => attachment_uuid, 'page' => 0 }
          ]
        }
      end
    end
    template.save!

    submission = FactoryBot.create(:submission, template:, account:)

    template.submitters.each do |item|
      FactoryBot.create(:submitter, submission:, account_id: account.id, uuid: item['uuid'])
    end

    submission
  end

  # Podepsané PDF bez appky (stejná pipeline jako produkce): TBS → CMS →
  # PAdES; `seal: true` přidá inkrementální pečeť DocuSealu. Pro testy
  # ověření (docs/16) stačí `signed_pdf` bez LTV.
  def signed_pdf(pkcs: pkcs12, seal: false, submitter: nil, tsa_url: nil)
    submitter ||= build_qes_submitter
    field = submitter.submission.template_fields.find { |f| f['type'] == 'qes' }
    tbs_pdf = Qes::TbsDocument.build(submitter, field)
    byte_range = Qes::TbsDocument.byte_range(tbs_pdf)
    data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), byte_range)
    prepared = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate,
                                      chain: pkcs.ca_certs, signing_time: Time.now.utc)
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), prepared[:signed_attrs_der])
    cms_der = Qes::CmsBuilder.complete(data:, signed_attrs_der: prepared[:signed_attrs_der],
                                        signature:, certificate: pkcs.certificate,
                                        chain: pkcs.ca_certs, tsa_url:)

    signed = Qes::Embed.call(tbs_pdf, cms_der)
    return signed unless seal

    Qes::Seal.apply(signed, submitter.account, submitter:, pkcs:)[0]
  end

  def self_signed_pkcs12
    key, certificate = self_signed_qc_sscd_certificate

    OpenSSL::PKCS12.create('test', 'test', key, certificate)
  end

  # Raw `/Contents` posledního podpisu (pro VRI klíč v DSS).
  def signature_contents(pdf_bytes)
    HexaPDF::Document.new(io: StringIO.new(pdf_bytes)).signatures.to_a.last[:Contents].to_s
  end

  # Testovací RFC 3161 token nad `io`/`byte_range` (PAdES-LTA testy).
  # `OpenSSL::PKCS7#data` je nil (stejně jako u DigiCert), takže testuje
  # i cestu s TSTInfo v `eContent` (SPEC § 7.6).
  def timestamp_token(io, byte_range, key: tsa_key, certificate: tsa_certificate)
    digest = OpenSSL::Digest.new('SHA256')

    byte_range.each_slice(2) do |offset, length|
      io.pos = offset
      digest << io.read(length)
    end

    build_timestamp_token(digest.digest, key:, certificate:)
  end

  def tsa_key
    tsa_key_and_certificate.first
  end

  def tsa_certificate
    tsa_key_and_certificate.last
  end

  def tsa_root_certificate
    tsa_root_key_and_certificate.last
  end

  def tsa_root_key_and_certificate
    @tsa_root_key_and_certificate ||= begin
      key = OpenSSL::PKey::RSA.new(2048)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = OpenSSL::BN.rand(64)
      certificate.subject = OpenSSL::X509::Name.parse('/C=CZ/O=QES Test/CN=Test TSA Root')
      certificate.issuer = certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = Time.current - 60
      certificate.not_after = Time.current + 365.days
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      factory.issuer_certificate = certificate
      certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      certificate.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
      certificate.sign(key, OpenSSL::Digest.new('SHA256'))

      [key, certificate]
    end
  end

  def tsa_key_and_certificate
    @tsa_key_and_certificate ||= begin
      key = OpenSSL::PKey::RSA.new(2048)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = OpenSSL::BN.rand(64)
      certificate.subject = OpenSSL::X509::Name.parse('/C=CZ/O=QES Test/CN=Test TSA')
      certificate.issuer = tsa_root_certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = Time.current - 60
      certificate.not_after = Time.current + 3600
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      factory.issuer_certificate = tsa_root_certificate
      certificate.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
      certificate.add_extension(factory.create_extension('extendedKeyUsage', 'timeStamping', true))
      certificate.sign(tsa_root_key_and_certificate.first, OpenSSL::Digest.new('SHA256'))

      [key, certificate]
    end
  end

  def build_timestamp_token(imprint, key:, certificate:, algorithm: 'SHA256', at: Time.current)
    digest_algorithm = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new('2.16.840.1.101.3.4.2.1'), OpenSSL::ASN1::Null.new(nil)
    ])
    tst_info = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(1),
      OpenSSL::ASN1::ObjectId.new('1.2.3.4.1'),
      OpenSSL::ASN1::Sequence.new([digest_algorithm, OpenSSL::ASN1::OctetString.new(imprint)]),
      OpenSSL::ASN1::Integer.new(OpenSSL::BN.rand(64)),
      OpenSSL::ASN1::GeneralizedTime.new(at.utc)
    ]).to_der
    attributes = OpenSSL::ASN1::Set.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.3'),
        OpenSSL::ASN1::Set.new([OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.16.1.4')])
      ]),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.4'),
        OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(
          OpenSSL::Digest.digest(algorithm, tst_info)
        )])
      ])
    ])
    signature = key.sign(OpenSSL::Digest.new(algorithm), attributes.to_der)
    signer_info = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(1),
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1.decode(certificate.issuer.to_der),
                                   OpenSSL::ASN1::Integer.new(certificate.serial)]),
      digest_algorithm,
      OpenSSL::ASN1::ASN1Data.new(attributes.value, 0, :CONTEXT_SPECIFIC),
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.1.11'),
                                   OpenSSL::ASN1::Null.new(nil)]),
      OpenSSL::ASN1::OctetString.new(signature)
    ])
    signed_data = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(3),
      OpenSSL::ASN1::Set.new([digest_algorithm]),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.16.1.4'),
        OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new(tst_info)], 0, :CONTEXT_SPECIFIC)
      ]),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1.decode(certificate.to_der)], 0, :CONTEXT_SPECIFIC),
      OpenSSL::ASN1::Set.new([signer_info])
    ])

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.2'),
      OpenSSL::ASN1::ASN1Data.new([signed_data], 0, :CONTEXT_SPECIFIC)
    ]).to_der
  end

  # `config.cache_store` je v testu `:null_store` (upstream); rate limiter
  # potřebuje skutečný store jen ve svých specách (M15).
  def stub_memory_cache!
    allow(Rails).to receive(:cache).and_return(ActiveSupport::Cache::MemoryStore.new)
  end

  def configure!
    Qes::Config.reset!
    Qes::Config[:enabled] = true
    Qes::Config[:trust_roots] = pki_path('root.crt').to_s
    Qes::Config[:require_ltv] = false
    Qes::Config[:tsa_url] = nil
    Qes::Config[:tsa_required] = false
    Qes::Config[:tsa_trust_roots] = nil
    # SSRF ochrana (SPEC § 7.4): testovací CRL server na 127.0.0.1 je explicitně povolený.
    Qes::Config[:ltv_allowed_hosts] = '127.0.0.1'
    Qes::Config[:seal_pkcs_path] = pki_path('signer-ades.p12').to_s
    Qes::Config[:seal_pkcs_password] = 'test'
  end

  # Self-signed certifikát s podvrženými QCStatements (QcCompliance + QcSSCD).
  # Musí být odmítnutý — nevede k trust rootu (SPEC § 5.2).
  def self_signed_qc_sscd_certificate
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse('/C=CZ/O=Untrusted/CN=Self Signed QES')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.current - 60
    cert.not_after = Time.current + 3600

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
    cert.add_extension(OpenSSL::X509::Extension.new('1.3.6.1.5.5.7.1.3', qc_statements_der))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end

  def qc_statements_der
    OpenSSL::ASN1::Sequence(
      [
        OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId.new('0.4.0.1862.1.1')]),
        OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId.new('0.4.0.1862.1.4')])
      ]
    )
  end

  # Spustí lokální HTTP server s CRL (127.0.0.1:8765/root.crl) pro dobu bloku.
  def with_crl_server(crl_name = 'root.crl')
    server = TCPServer.new('127.0.0.1', CRL_PORT)
    body = pki_path(crl_name).binread

    thread = Thread.new do
      loop do
        socket = server.accept
        socket.gets
        socket.gets until socket.gets.to_s.strip.empty?
        socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\n" \
                     "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n")
        socket.write(body)
        socket.close
      end
    rescue IOError, Errno::EBADF
      nil
    end

    yield
  ensure
    server&.close
    thread&.kill
  end
end

RSpec.configure do |config|
  config.include QesHelpers
end
