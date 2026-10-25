# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::Seal do
  before { QesHelpers.configure! }

  it 'distinguishes an unconfigured seal from a failed configured seal' do
    submitter = QesHelpers.build_qes_submitter
    Qes::Config[:seal_pkcs_path] = nil
    stub_const('Docuseal::CERTS', nil)
    allow(Docuseal).to receive(:multitenant?).and_return(false)
    allow(EncryptedConfig).to receive(:exists?).with(key: EncryptedConfig::ESIGN_CERTS_KEY).and_return(false)
    expect(Accounts).not_to receive(:load_signing_pkcs)

    expect(described_class.apply('document', submitter.account, submitter:)).to eq(['document', 'none'])
    expect(described_class.apply('invalid PDF', submitter.account, submitter:, pkcs: QesHelpers.pkcs12))
      .to eq(['invalid PDF', 'failed'])
  end
end
