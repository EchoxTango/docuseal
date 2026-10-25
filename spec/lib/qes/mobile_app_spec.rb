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
