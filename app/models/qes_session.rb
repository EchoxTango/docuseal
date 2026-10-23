# frozen_string_literal: true

# == Schema Information
#
# Table name: qes_sessions
#
#  id                  :bigint           not null, primary key
#  account_id          :bigint           not null
#  submission_id       :bigint           not null
#  submitter_id        :bigint           not null
#  field_uuid          :string           not null
#  provider            :string           not null (mobile_app, mock)
#  state               :string           not null
#  token_digest        :string
#  hash_algorithm      :string           not null
#  signature_algorithm :string           not null
#  level               :string
#  key_location        :string
#  certificate_info    :text (JSON)
#  certificate_chain   :text (JSON)
#  signed_attrs_der    :binary
#  signature           :binary
#  document_digest     :string
#  signed_pdf_sha256   :string
#  final_pdf_sha256    :string
#  validation_report   :text (JSON)
#  seal_state          :string           not null (none, applied, failed)
#  doc_timestamp_state :string           not null (none, applied, failed)
#  app_metadata        :text (JSON)
#  expires_at          :datetime
#  prepared_at         :datetime
#  app_opened_at       :datetime
#  signed_at           :datetime
#  embedded_at         :datetime
#  validated_at        :datetime
#  completed_at        :datetime
#  failed_at           :datetime
#  failure_code        :string
#  failure_message     :string
#
class QesSession < ApplicationRecord
  belongs_to :account
  belongs_to :submission
  belongs_to :submitter

  has_one_attached :tbs_document
  has_one_attached :signed_document
  has_one_attached :final_document

  attribute :certificate_info, :string
  attribute :certificate_chain, :string
  attribute :validation_report, :string
  attribute :app_metadata, :string

  serialize :certificate_info, coder: JSON
  serialize :certificate_chain, coder: JSON
  serialize :validation_report, coder: JSON
  serialize :app_metadata, coder: JSON

  enum :seal_state, { none: 'none', applied: 'applied', failed: 'failed' }, prefix: :seal,
       default: 'none', validate: true

  enum :doc_timestamp_state, { none: 'none', applied: 'applied', failed: 'failed' },
       prefix: :doc_timestamp, default: 'none', validate: true

  scope :active, -> { where(state: Qes::SessionManager::ACTIVE_STATES) }
  scope :completed, -> { where(state: 'completed') }
  scope :stale, -> { active.where(expires_at: ..Time.current) }

  validate :field_uuid_must_be_qes_field

  # `ApplicationRecord#strip_attributes` maže whitespace i z binárních sloupců
  # (`signature`, `signed_attrs_der`). Podpis jsou náhodné bajty, takže ~5 %
  # podpisů by se po validaci uložilo poškozených (a idempotence by selhala).
  BINARY_ATTRIBUTES = %i[signature signed_attrs_der].freeze

  before_validation :remember_binary_attributes, prepend: true
  after_validation :restore_binary_attributes

  # Session pole pro pole `qes` (stejná logika jako ve views, SPEC § 14).
  def self.completed_for(submitter, field_uuid)
    submitter&.qes_sessions&.completed&.find { |session| session.field_uuid == field_uuid }
  end

  def value_token
    "qes:#{id}"
  end

  def field
    Qes.template_field(submission, field_uuid)
  end

  def level_required
    field&.dig('preferences', 'level').presence || 'ades'
  end

  def terminal?
    Qes::SessionManager.terminal?(state)
  end

  def expired?(at = Time.current)
    state == 'expired' || expires_at.present? && expires_at <= at
  end

  def certificate
    return nil if certificate_chain.blank?

    OpenSSL::X509::Certificate.new(Base64.decode64(certificate_chain.first))
  end

  private

  def remember_binary_attributes
    @binary_attributes = BINARY_ATTRIBUTES.index_with { |name| public_send(name) }
  end

  def restore_binary_attributes
    return if @binary_attributes.nil?

    BINARY_ATTRIBUTES.each { |name| public_send(:"#{name}=", @binary_attributes[name]) }
  end

  def field_uuid_must_be_qes_field
    return if field_uuid.blank? || submitter.blank?

    fields = Qes.template_fields(submission)
    field = fields.find { |f| f['uuid'] == field_uuid }

    errors.add(:field_uuid, 'must be a qes field of the submitter') if field.nil?
    errors.add(:field_uuid, 'must belong to the submitter') if field && field['submitter_uuid'] != submitter.uuid
    errors.add(:field_uuid, 'must be a qes field') if field && field['type'] != 'qes'
  end
end
