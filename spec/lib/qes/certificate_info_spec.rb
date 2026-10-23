# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::CertificateInfo do
  describe '.parse' do
    it 'maps QcCompliance to ades' do
      info = described_class.parse(QesHelpers.pki_path('signer-ades.crt').binread)

      expect(info.level).to eq('ades')
      expect(info.qc_statements).to eq(['QcCompliance'])
      expect(info.digital_signature?).to be true
    end

    it 'maps QcCompliance + QcSSCD to qes' do
      info = described_class.parse(QesHelpers.pki_path('signer-qscd.crt').binread)

      expect(info.level).to eq('qes')
      expect(info.qc_statements).to contain_exactly('QcCompliance', 'QcSSCD')
    end

    it 'returns none for a certificate without QCStatements' do
      info = described_class.parse(File.binread(QesHelpers::TEST_DIR.join('certs', 'signer.cert.pem')))

      expect(info.level).to eq('none')
    end

    it 'rejects an expired certificate' do
      info = described_class.parse(QesHelpers.pki_path('signer-expired.crt').binread)

      expect { info.validate!(level_required: 'ades', key_location: 'phone_keystore') }
        .to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:certificate_expired) }
    end

    it 'rejects a QcSSCD certificate used from the phone keystore' do
      info = described_class.parse(QesHelpers.pki_path('signer-qscd.crt').binread)

      expect { info.validate!(level_required: 'ades', key_location: 'phone_keystore') }
        .to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:level_mismatch) }
    end

    it 'requires QcSSCD for a qes field' do
      info = described_class.parse(QesHelpers.pki_path('signer-ades.crt').binread)

      expect { info.validate!(level_required: 'qes', key_location: 'phone_keystore') }
        .to raise_error(Qes::ClientError) { |e| expect(e.code).to eq(:qes_required_qscd) }
    end

    it 'accepts an ades certificate from the phone keystore' do
      info = described_class.parse(QesHelpers.pki_path('signer-ades.crt').binread)

      expect(info.validate!(level_required: 'ades', key_location: 'phone_keystore'))
        .to include(level: 'ades', key_type: 'rsa')
    end
  end
end
