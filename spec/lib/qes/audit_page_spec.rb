# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::AuditPage do
  before { QesHelpers.configure! }

  it 'distinguishes CMS signing time, completion and verified timestamp evidence' do
    session = create(:qes_session, signing_time: Time.utc(2026, 10, 25, 10),
                                   completed_at: Time.utc(2026, 10, 25, 10, 5),
                                   doc_timestamp_state: 'applied',
                                   validation_report: {
                                     signer_validation: { time_source: 'timestamp',
                                                          validated_at_time: '2026-10-25T10:04:00Z' },
                                     doc_timestamp: { timestamp_time: '2026-10-25T10:04:30Z' }
                                   })

    I18n.with_locale(:cs) do
      rows = described_class.rows_for(session).to_h
      expect(rows).to include('Čas podpisu' => '2026-10-25T10:00:00Z',
                              'Dokončeno' => '2026-10-25T10:05:00Z',
                              'Dokumentové razítko (DocTS)' => 'applied',
                              'Čas dokumentového razítka' => '2026-10-25T10:04:30Z',
                              'Čas ověření certifikátu' => '2026-10-25T10:04:00Z',
                              'Zdroj času validace' => 'Ověřené časové razítko')
    end
  end

  it 'does not substitute completion for the unknown signing time of an older session' do
    session = create(:qes_session, completed_at: Time.current, signing_time: nil,
                                   validation_report: { signatures: [{ qes: true, time_source: 'current' }] })

    I18n.with_locale(:cs) do
      rows = described_class.time_rows(session).to_h
      expect(rows).not_to have_key('Čas podpisu')
      expect(rows).not_to have_key('Čas dokumentového razítka')
      expect(rows).to include('Dokončeno' => session.completed_at.utc.iso8601,
                              'Zdroj času validace' => 'Aktuální čas')
    end
  end
end
