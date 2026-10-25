# frozen_string_literal: true

# QES/AdES podpisový obřad (dokulachtan fork).
#
# Server nikdy nevidí privátní klíč podepisujícího: dostane jen certifikát,
# podepsané atributy CMS a raw signaturu, kterou vloží do PDF (PAdES).
# Design: DESIGN.md, detailní specifikace: SPEC.md.
module Qes
  class Error < StandardError; end

  # Neplatný přechod stavového automatu (SPEC § 4.3).
  class InvalidTransition < Error; end

  # Chyba, kterou lze bezpečně vrátit klientovi jako 422 s `code`.
  class ClientError < Error
    attr_reader :code

    def initialize(code, message = nil)
      @code = code
      super(message || code.to_s)
    end
  end

  # Konfigurace QES (SPEC § 11). Hodnoty se čtou z ENV, testy je mohou přepsat.
  module Config
    DEFAULTS = {
      enabled: false,
      session_ttl: 600,
      pdf_max_bytes: 25.megabytes,
      signature_size: 20_000,
      signature_min_size: 20_000,
      signature_size_margin: 16_384,
      seal_pkcs_path: nil,
      seal_pkcs_password: nil,
      deep_link_base: 'dokulachtan://sign',
      public_base_url: nil,
      trust_roots: nil,
      tsa_url: nil,
      tsa_trust_roots: nil,
      tsa_required: true,
      require_ltv: false,
      ltv_allowed_hosts: nil,
      android_cert_sha256: nil,
      ios_team_id: nil,
      expiry_job_interval: 60
    }.freeze

    class << self
      def [](key)
        overrides.fetch(key) { from_env(key) }
      end

      def []=(key, value)
        overrides[key] = value
      end

      def reset!
        @overrides = {}
      end

      def overrides
        @overrides ||= {}
      end

      private

      def from_env(key)
        env_name = "QES_#{key.to_s.upcase}"
        return DEFAULTS[key] unless ENV.key?(env_name)

        cast(ENV[env_name], DEFAULTS[key])
      end

      def cast(raw, default)
        case default
        when true, false then ActiveModel::Type::Boolean.new.cast(raw)
        when Integer then raw.to_i
        else raw.presence
        end
      end
    end
  end

  # Trust roots pro ověření QES/AdES (SPEC § 5.2 a § 7.5). Načítá se ze
  # stejné konfigurace jako při podpisu, aby ověření a podpis měly jeden zdroj pravdy.
  def self.trust_roots
    paths = Config[:trust_roots]
    paths = paths.split(',') if paths.is_a?(String)

    Array(paths).flat_map do |path|
      path = path.strip
      next [] if path.blank? || !File.exist?(path)

      OpenSSL::X509::Certificate.load_file(path)
    end
  end

  # Samostatné kořeny důvěry pro časová razítka.
  def self.tsa_trust_roots
    paths = Config[:tsa_trust_roots]
    paths = paths.split(',') if paths.is_a?(String)

    Array(paths).flat_map do |path|
      path = path.strip
      next [] if path.blank? || !File.exist?(path)

      OpenSSL::X509::Certificate.load_file(path)
    end
  end

  # Pole šablony submissionu. U submissions vytvořených z UI bývá `template_fields`
  # prázdné (plní se až při odeslání formuláře) — stejný fallback jako upstream
  # (`submission.template_fields || submission.template.fields`).
  def self.template_fields(submission)
    submission.template_fields.presence || submission.template&.fields || []
  end

  # Pole šablony podle uuid (a volitelně submittera); používá controller i model.
  def self.template_field(submission, uuid, submitter_uuid: nil)
    template_fields(submission).find do |field|
      field['uuid'] == uuid && (submitter_uuid.nil? || field['submitter_uuid'] == submitter_uuid)
    end
  end

  def self.template_schema(submission)
    submission.template_schema.presence || submission.template&.schema || []
  end

  # Bezpečné logování bez osobních údajů (SPEC § 7.9).
  def self.log(session, message = nil)
    parts = ["[qes]", "session=#{session.id}", "submission=#{session.submission_id}",
             "submitter=#{session.submitter_id}", "state=#{session.state}"]
    parts << "level=#{session.level}" if session.level.present?
    parts << "code=#{session.failure_code}" if session.failure_code.present?
    parts << message if message
    Rails.logger.info(parts.join(' '))
  end
end
