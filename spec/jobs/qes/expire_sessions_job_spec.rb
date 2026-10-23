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
end
