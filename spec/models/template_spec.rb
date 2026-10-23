# frozen_string_literal: true

require 'rails_helper'

# Validace šablony pro vícenásobné QES podpisy (SPEC § 4.1, § 7.7).
RSpec.describe Template do
  def build_template!(**options)
    account = create(:account)
    user = create(:user, account:)

    create(:template, account:, author: user, **options)
  end

  def add_qes_fields!(template, submitters: template.submitters)
    attachment_uuid = template.schema.first['attachment_uuid']

    template.fields += submitters.map do |submitter|
      {
        'uuid' => SecureRandom.uuid,
        'submitter_uuid' => submitter['uuid'],
        'name' => 'QES signature',
        'type' => 'qes',
        'required' => true,
        'preferences' => {},
        'areas' => [
          { 'x' => 0.1, 'y' => 0.8, 'w' => 0.3, 'h' => 0.06,
            'attachment_uuid' => attachment_uuid, 'page' => 0 }
        ]
      }
    end

    template
  end

  it 'requires a qes field for every signer' do
    template = build_template!(only_field_types: %w[text], submitter_count: 2)

    add_qes_fields!(template, submitters: template.submitters.first(1))

    expect(template.save).to be false
    expect(template.errors[:fields]).to include('qes_all_signers_required')
  end

  it 'requires preserved order for multiple signers' do
    template = add_qes_fields!(build_template!(only_field_types: %w[text], submitter_count: 2))

    expect(template.save).to be false
    expect(template.errors[:fields]).to include('qes_signing_order_required')
  end

  it 'rejects parallel signers with the same order' do
    template = build_template!(only_field_types: %w[text], submitter_count: 2)
    template.submitters = template.submitters.map { |submitter| submitter.merge('order' => 1) }

    add_qes_fields!(template)

    expect(template.save).to be false
    expect(template.errors[:fields]).to include('qes_parallel_signers_not_allowed')
  end

  it 'accepts multiple signers with preserved order' do
    template = build_template!(only_field_types: %w[text], submitter_count: 2)
    template.preferences = template.preferences.merge('submitters_order' => 'preserved')

    add_qes_fields!(template)

    expect(template.save).to be true
  end

  it 'accepts multiple signers with distinct order' do
    template = build_template!(only_field_types: %w[text], submitter_count: 2)
    template.submitters = template.submitters.each_with_index.map { |submitter, index| submitter.merge('order' => index) }

    add_qes_fields!(template)

    expect(template.save).to be true
  end

  it 'accepts a single signer without preserved order' do
    template = add_qes_fields!(build_template!(only_field_types: %w[text]))

    expect(template.save).to be true
  end
end
