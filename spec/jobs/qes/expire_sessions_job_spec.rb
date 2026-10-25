# frozen_string_literal: true

require 'rails_helper'

# Expirace sessions (SPEC § 7.8): `reschedule!` musí proběhnout i při výjimce,
# jinak se smyčka expirace po DB timeoutu zastaví (M7).
RSpec.describe Qes::ExpireSessionsJob do
  before { QesHelpers.configure! }

  it 'reschedules even when a transition raises' do
    allow(QesSession).to receive(:stale).and_raise(ActiveRecord::StatementInvalid, 'timeout')
    allow(described_class).to receive(:perform_in)

    expect { described_class.new.perform }.to raise_error(ActiveRecord::StatementInvalid)
    expect(described_class).to have_received(:perform_in)
  end
  it 'does not overwrite a session completed after the stale query' do
    session = create(:qes_session, state: 'awaiting_signature', expires_at: 1.minute.ago)
    stale = QesSession.stale
    allow(QesSession).to receive(:stale).and_return(stale)
    allow(stale).to receive(:find_each).and_wrap_original do |_original, &block|
      QesSession.where(id: session.id).update_all(state: 'completed', completed_at: Time.current)
      block.call(session)
    end
    allow(described_class).to receive(:perform_in)

    described_class.new.perform

    expect(session.reload.state).to eq('completed')
    expect(session.failure_code).to be_nil
  end

  it 'expires an active stale session' do
    session = create(:qes_session, state: 'awaiting_signature', expires_at: 1.minute.ago)
    allow(described_class).to receive(:perform_in)

    described_class.new.perform

    expect(session.reload.state).to eq('expired')
    expect(session.failure_code).to eq('expired')
  end
end
