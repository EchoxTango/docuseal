# frozen_string_literal: true

require 'rails_helper'

RSpec.describe QesSession do
  before { QesHelpers.configure! }

  describe 'validations' do
    it 'requires a qes field of the submitter' do
      submitter = QesHelpers.build_qes_submitter
      other_field = submitter.submission.template_fields.find { |f| f['type'] == 'text' }

      session = build(:qes_session, submitter:, submission: submitter.submission,
                                      account: submitter.account, field_uuid: other_field['uuid'])

      expect(session).not_to be_valid
      expect(session.errors[:field_uuid]).to be_present
    end

    it 'accepts a qes field of the submitter' do
      expect(build(:qes_session)).to be_valid
    end
  end

  describe 'state machine' do
    it 'walks the happy path to completed' do
      session = create(:qes_session)

      expect(session.state).to eq('created')

      Qes::SessionManager.transition!(session, 'prepared')
      Qes::SessionManager.transition!(session, 'awaiting_app')
      Qes::SessionManager.transition!(session, 'app_opened')
      Qes::SessionManager.transition!(session, 'awaiting_signature')
      Qes::SessionManager.transition!(session, 'signed')
      Qes::SessionManager.transition!(session, 'embedded')
      Qes::SessionManager.transition!(session, 'validated')
      Qes::SessionManager.transition!(session, 'completed')

      expect(session.state).to eq('completed')
      expect(session.completed_at).to be_present
      expect(session.signed_at).to be_present
    end

    it 'rejects a forbidden transition' do
      session = create(:qes_session)

      expect { Qes::SessionManager.transition!(session, 'completed') }
        .to raise_error(Qes::InvalidTransition)
    end
  end


  it 'resolves the field when the submission has blank template_fields' do
    submitter = QesHelpers.build_qes_submitter
    submitter.submission.update!(template_fields: nil, template_schema: nil)
    field = submitter.submission.template.fields.find { |f| f['type'] == 'qes' }
    session = create(:qes_session, submitter:, submission: submitter.submission,
                                   account: submitter.account, field_uuid: field['uuid'])

    expect(session.field).to be_present
    expect(session.field['uuid']).to eq(field['uuid'])
    expect(session.level_required).to eq('ades')
  end

  it 'exposes the qes:<id> value token' do
    session = create(:qes_session)

    expect(session.value_token).to eq("qes:#{session.id}")
  end

  it 'keeps the token digest until retention' do
    token = Qes::Token.generate
    session = create(:qes_session, token_digest: Qes::Token.digest(token), state: 'completed')

    expect(Qes::Token.find(token)).to eq(session)
  end

  describe 'scopes' do
    it 'finds active and completed sessions' do
      active = create(:qes_session, state: 'awaiting_app')
      completed = create(:qes_session, state: 'completed')

      expect(described_class.active).to include(active)
      expect(described_class.completed).to include(completed)
      expect(described_class.active).not_to include(completed)
    end

    it 'finds stale sessions' do
      stale = create(:qes_session, state: 'awaiting_app', expires_at: 1.minute.ago)
      create(:qes_session, state: 'awaiting_app', expires_at: 10.minutes.from_now)

      expect(described_class.stale).to include(stale)
    end
  end

  it 'keeps binary signature bytes intact through validation' do
    signature = (10.chr + 'ab' + 10.chr).b
    signed_attrs_der = (10.chr + 'cd' + 10.chr).b
    session = build(:qes_session, signature:, signed_attrs_der:)

    session.valid?

    expect(session.signature).to eq(signature)
    expect(session.signed_attrs_der).to eq(signed_attrs_der)
  end

  it 'expires a stale session and keeps the token digest' do
    token = Qes::Token.generate
    session = create(:qes_session, token_digest: Qes::Token.digest(token),
                                   state: 'awaiting_app', expires_at: 1.minute.ago)

    expect(session.expired?).to be true

    Qes::SessionManager.transition!(session, 'expired', failure_code: 'expired')

    expect(session.reload.state).to eq('expired')
    expect(session.failure_code).to eq('expired')
    expect(Qes::Token.find(token)).to eq(session)
  end
end
