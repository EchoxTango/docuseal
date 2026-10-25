# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::Providers::MobileApp do
  before do
    QesHelpers.configure!
    allow(Qes::Ltv).to receive(:fetch_crls).and_return([])
  end

  let(:session) { create(:qes_session, state: 'awaiting_app') }
  let(:provider) { described_class.new(session) }
  let(:pkcs) { QesHelpers.pkcs12 }

  def prepare_document
    provider.data_to_sign(pkcs.certificate.to_der, chain: pkcs.ca_certs || [],
                                                 key_location: 'phone_keystore')
  end

  it 'stores the exact CMS signingTime before completion' do
    prepare_document

    expect(session.reload.signing_time).to eq(Qes::CmsBuilder.signing_time_from(session.signed_attrs_der))
    expect(session.completed_at).to be_nil
  end

  it 'still rejects values changed after the preparation lock was released' do
    field = session.submission.template_fields.find { |item| item['type'] == 'text' }
    allow(Qes::CmsBuilder).to receive(:prepare).and_wrap_original do |original, **args|
      session.submitter.update!(values: { field['uuid'] => 'Changed during preparation' })
      original.call(**args)
    end

    expect { prepare_document }.to raise_error(Qes::ClientError) do |error|
      expect(error.code).to eq(:values_changed)
    end
    expect(session.reload.state).to eq('awaiting_app')
    expect(session.tbs_document).not_to be_attached
  end

  it 'does not complete or publish documents when the configured seal fails' do
    prepare_document
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)
    allow(Qes::Seal).to receive(:apply) { |pdf, *| [pdf, 'failed'] }

    expect { provider.complete!(signature) }
      .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:seal_failed) }
    expect(session.reload.state).to eq('awaiting_signature')
    expect(session.signed_document).not_to be_attached
    expect(session.final_document).not_to be_attached
    expect(session.submitter.reload.values[session.field_uuid]).to be_nil
  end

  [false, true].each do |required|
    it "rejects a TSA URL without trust roots before completion (tsa_required=#{required})" do
      prepare_document
      Qes::Config[:tsa_url] = 'http://tsa.test'
      Qes::Config[:tsa_required] = required
      signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)
      expect(provider).not_to receive(:ltv_values)
      expect(provider).not_to receive(:build_cms)
      expect(Qes::DocTimestamp).not_to receive(:apply)

      expect { provider.complete!(signature) }.to raise_error(Qes::ClientError) do |error|
        expect(error.code).to eq(:tsa_trust_not_configured)
        expect(error.message).to include('QES_TSA_TRUST_ROOTS')
      end
      expect(session.reload.state).to eq('awaiting_signature')
      expect(session.signed_document).not_to be_attached
      expect(session.final_document).not_to be_attached
      expect(session.submitter.reload.values[session.field_uuid]).to be_nil
    end
  end

  it 'reports invalid_pdf if the prepared document has no byte range' do
    prepare_document
    allow(Qes::TbsDocument).to receive(:byte_range).and_return(nil)

    expect { provider.build_cms('signature') }
      .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:invalid_pdf) }
  end

  it 'keeps the session unprepared when uploading the TBS fails' do
    session
    allow(ActiveStorage::Blob).to receive(:create_and_upload!).and_raise(IOError, 'storage unavailable')

    expect { prepare_document }.to raise_error(IOError, 'storage unavailable')
    expect(session.reload.state).to eq('awaiting_app')
    expect(session.tbs_document).not_to be_attached
    expect(session.signed_attrs_der).to be_nil
  end

  %w[qes-signed qes-final].each do |prefix|
    it "does not complete when uploading #{prefix} fails" do
      prepare_document
      signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)
      allow(ActiveStorage::Blob).to receive(:create_and_upload!).and_wrap_original do |original, **args|
        raise IOError, 'storage unavailable' if args[:filename].start_with?(prefix)

        original.call(**args)
      end

      expect { provider.complete!(signature) }.to raise_error(IOError, 'storage unavailable')
      expect(session.reload.state).to eq('awaiting_signature')
      expect(session.completed_at).to be_nil
      expect(session.signed_document).not_to be_attached
      expect(session.final_document).not_to be_attached
      expect(session.submitter.reload.values[session.field_uuid]).to be_nil
    end
  end

  it 'uploads all bytes before entering the state-changing locks' do
    allow(session).to receive(:with_lock).and_wrap_original do |original, &block|
      prefix = session.state == 'awaiting_app' ? 'qes-tbs' : 'qes-final'
      blob = ActiveStorage::Blob.find_by!(filename: "#{prefix}-#{session.id}.pdf")
      expect(blob.download).to start_with('%PDF-')
      original.call(&block)
    end

    prepare_document
    signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), session.signed_attrs_der)
    provider.complete!(signature)

    expect(session.reload.state).to eq('completed')
    expect(session.final_document.download).to start_with('%PDF-')
  end
end
