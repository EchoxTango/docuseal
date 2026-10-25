# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'QES revocation failures through the signing pipeline' do
  before do
    QesHelpers.configure!
    allow(Qes).to receive(:trust_roots).and_return([root])
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(fresh_crl)
  end

  let(:root_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:root) do
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = OpenSSL::X509::Name.parse('/CN=Revocation test root')
    certificate.issuer = certificate.subject
    certificate.public_key = root_key.public_key
    certificate.not_before = 1.day.ago
    certificate.not_after = 1.day.from_now
    factory = OpenSSL::X509::ExtensionFactory.new
    certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    certificate.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    certificate.sign(root_key, OpenSSL::Digest.new('SHA256'))
    certificate
  end
  let(:leaf_pair) do
    key, certificate = QesHelpers.self_signed_qc_sscd_certificate
    certificate.issuer = root.subject
    factory = OpenSSL::X509::ExtensionFactory.new
    certificate.add_extension(factory.create_extension('crlDistributionPoints', 'URI:https://crl.test/root.crl'))
    certificate.sign(root_key, OpenSSL::Digest.new('SHA256'))
    [key, certificate]
  end
  let(:certificate) { leaf_pair.last }
  let(:session) { create(:qes_session, state: 'awaiting_app') }
  let(:provider) { Qes::Providers::MobileApp.new(session) }
  let(:fresh_crl) { make_crl }

  def make_crl(problem = nil)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = problem == :wrong_issuer ? OpenSSL::X509::Name.parse('/CN=Other root') : root.subject
    crl.last_update = problem == :future ? 1.hour.from_now : 1.hour.ago
    crl.next_update = problem == :stale ? 10.minutes.ago : 2.hours.from_now
    key = problem == :invalid_signature ? OpenSSL::PKey::RSA.new(2048) : root_key
    crl.sign(key, OpenSSL::Digest.new('SHA256'))
    crl
  end

  def prepare_document(**options)
    provider.data_to_sign(certificate.to_der, chain: [root], key_location: 'card', **options)
  end

  [false, true].each do |required|
    %i[stale future wrong_issuer invalid_signature unavailable].each do |problem|
      %i[data_to_sign complete].each do |stage|
        it "fails closed for #{problem} during #{stage}, require_ltv=#{required}" do
          Qes::Config[:require_ltv] = required
          if stage == :complete
            prepare_document
            signature = leaf_pair.first.sign(OpenSSL::Digest.new('SHA256'), session.reload.signed_attrs_der)
            expect(provider).not_to receive(:build_cms)
            expect(provider).not_to receive(:embed)
          end
          if problem == :unavailable
            allow(Qes::Ltv).to receive(:fetch_first_crl).and_raise(Qes::Ltv::FetchError, 'CRL unavailable')
          else
            allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(make_crl(problem))
          end
          values = session.submitter.reload.values.deep_dup

          expect { stage == :complete ? provider.complete!(signature) : prepare_document }
            .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:ltv_unavailable) }
          expect(session.reload.state).to eq(stage == :complete ? 'awaiting_signature' : 'awaiting_app')
          expect(session.final_document).not_to be_attached
          expect(session.signed_document).not_to be_attached
          expect(session.tbs_document).not_to be_attached if stage == :data_to_sign
          expect(session.submitter.reload.values).to eq(values)
        end
      end
    end
  end

  [[], :stale, :wrong_issuer, :invalid_signature].each do |provided|
    it "rejects supplied CRLs #{provided.inspect} without bypassing distribution point checks" do
      crls = provided.is_a?(Array) ? provided : [make_crl(provided)]

      expect { prepare_document(crls:) }
        .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:ltv_unavailable) }
      expect(session.reload.state).to eq('awaiting_app')
      expect(session.tbs_document).not_to be_attached
    end
  end
end
