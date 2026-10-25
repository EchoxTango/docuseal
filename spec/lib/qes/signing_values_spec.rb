# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::SigningValues do
  before { QesHelpers.configure! }

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:submission) { submitter.submission }
  let(:text_field) { submission.template_fields.find { |field| field['type'] == 'text' } }

  def add_field(**attrs)
    field = text_field.deep_dup.merge('uuid' => SecureRandom.uuid, 'name' => 'Additional field')
                      .merge(attrs.stringify_keys)
    submission.update!(template_fields: submission.template_fields + [field])
    field
  end

  [nil, '', '   ', [], false].each do |value|
    it "rejects a blank required value (#{value.inspect})" do
      submitter.update!(values: { text_field['uuid'] => value })

      expect { described_class.validate!(submitter) }.to raise_error(described_class::IncompleteFields) do |error|
        expect(error.code).to eq(:fields_incomplete)
        expect(error.missing_fields).to eq([text_field['name']])
      end
    end
  end

  it 'reports all missing names with a UUID fallback for unnamed fields' do
    second = add_field(name: '')
    submitter.update!(values: {})

    expect { described_class.validate!(submitter) }.to raise_error(described_class::IncompleteFields) do |error|
      expect(error.missing_fields).to eq([text_field['name'], second['uuid']])
    end
  end

  it 'accepts zero and ignores optional, readonly, QES and other submitters fields' do
    submitter.update!(values: { text_field['uuid'] => 0 })
    add_field(required: false)
    add_field(readonly: true)
    add_field(submitter_uuid: SecureRandom.uuid)

    expect { described_class.validate!(submitter) }.not_to raise_error
  end

  it 'uses effective defaults and removes hidden field values without persisting a preview' do
    text_field['default_value'] = 'Default name'
    submission.update!(template_fields: submission.template_fields)
    hidden = add_field(conditions: [{ 'field_uuid' => text_field['uuid'], 'action' => 'empty' }])
    submitter.update!(values: { hidden['uuid'] => 'Obsolete value' })

    expect { described_class.validate!(submitter) }.not_to raise_error
    expect(submitter.reload.values).to eq(hidden['uuid'] => 'Obsolete value')

    submitter.with_lock do
      described_class.prepare!(submitter)
      submitter.save!
    end
    expect(submitter.reload.values).to eq(text_field['uuid'] => 'Default name')
    expect(submitter.completed_at).to be_nil
  end

  it 'requires a conditional field only while its condition holds' do
    conditional = add_field(conditions: [{ 'field_uuid' => text_field['uuid'], 'action' => 'equal', 'value' => 'Yes' }])
    expect { described_class.validate!(submitter) }.not_to raise_error
    submitter.update!(values: { text_field['uuid'] => 'Yes' })

    expect { described_class.validate!(submitter) }.to raise_error(described_class::IncompleteFields) do |error|
      expect(error.missing_fields).to eq([conditional['name']])
    end
  end

  it 'ignores required fields on documents excluded by conditions' do
    schema = submission.template_schema.deep_dup
    schema.first['conditions'] = [{ 'field_uuid' => text_field['uuid'], 'action' => 'not_empty' }]
    submission.update!(template_schema: schema)
    submitter.update!(values: {})

    expect { described_class.validate!(submitter) }.not_to raise_error
  end

  it 'evaluates conditions using another submitters values' do
    other_submission = QesHelpers.build_qes_submission(count: 2)
    first, second = other_submission.submitters.order(:id).to_a
    first_text, second_text = other_submission.template_fields.select { |field| field['type'] == 'text' }
    second_text['conditions'] = [{ 'field_uuid' => first_text['uuid'], 'action' => 'equal', 'value' => 'Yes' }]
    other_submission.update!(template_fields: other_submission.template_fields)
    second.update!(values: {})

    expect { described_class.validate!(second) }.not_to raise_error
    first.update!(values: { first_text['uuid'] => 'Yes' })
    expect { described_class.validate!(second) }.to raise_error(described_class::IncompleteFields) do |error|
      expect(error.missing_fields).to eq([second_text['name']])
    end
  end

  it 'requires verification before signing and accepts the completed verification event' do
    verification = add_field(type: 'verification')
    expect { described_class.validate!(submitter) }.to raise_error(described_class::IncompleteFields) do |error|
      expect(error.missing_fields).to eq([verification['name']])
    end

    submitter.submission_events.create!(event_type: 'complete_verification')
    expect { described_class.validate!(submitter) }.not_to raise_error
  end

  it 'resolves a prefilled current-date placeholder before signing' do
    date = add_field(type: 'date', readonly: true)
    submitter.update!(values: submitter.values.merge(date['uuid'] => '{{date}}'))

    described_class.prepare!(submitter)

    expect(submitter.values[date['uuid']]).to eq(TimeUtils.current_date_value(nil, submitter.account.timezone))
    expect(submitter.completed_at).to be_nil
  end

  it 'prepares a stamp at signing time without completing the submitter or regenerating it later' do
    stamp = add_field(type: 'stamp')
    attachment = Struct.new(:uuid).new('prepared-stamp')
    allow(Submitters::CreateStampAttachment).to receive(:build_attachment)
    described_class.validate!(submitter)
    expect(Submitters::CreateStampAttachment).not_to have_received(:build_attachment)
    expect(Submitters::CreateStampAttachment).to receive(:build_attachment).once do |signer, **|
      expect(signer.completed_at).to be_present
      attachment
    end

    submitter.with_lock do
      described_class.prepare!(submitter)
      submitter.save!
    end
    expect(submitter.reload.completed_at).to be_nil
    expect(submitter.values[stamp['uuid']]).to eq('prepared-stamp')
    create(:qes_session, :with_values_snapshot, submitter:, state: 'completed', level: 'ades')

    Submitters::SubmitValues.finalize_values!(submitter)
    expect(submitter.values[stamp['uuid']]).to eq('prepared-stamp')
  end

  it 'rejects direct provider calls before building a TBS with incomplete fields' do
    allow(Qes::Ltv).to receive(:fetch_first_crl).and_return(QesHelpers.crl)
    submitter.update!(values: {})
    session = create(:qes_session, submitter:, state: 'awaiting_app')
    pkcs = QesHelpers.pkcs12
    expect(Qes::TbsDocument).not_to receive(:build)

    expect do
      Qes::Providers::MobileApp.new(session).data_to_sign(pkcs.certificate.to_der, chain: pkcs.ca_certs || [],
                                                                                key_location: 'phone_keystore')
    end.to raise_error(described_class::IncompleteFields)
    expect(session.reload.state).to eq('awaiting_app')
    expect(session.tbs_document).not_to be_attached
  end
end
