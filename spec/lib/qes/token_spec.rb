# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::Token do
  before { QesHelpers.configure! }

  it 'generates a 43 character urlsafe token' do
    token = described_class.generate

    expect(token.size).to eq(43)
    expect(token).to match(/\A[\w-]+\z/)
  end

  it 'stores only the digest' do
    token = described_class.generate
    session = create(:qes_session, token_digest: described_class.digest(token))

    expect(described_class.find(token)).to eq(session)
    expect(session.reload.token_digest).to eq(Digest::SHA256.hexdigest(token))
  end

  it 'returns nil for unknown and blank tokens' do
    expect(described_class.find('unknown')).to be_nil
    expect(described_class.find(nil)).to be_nil
  end
end
