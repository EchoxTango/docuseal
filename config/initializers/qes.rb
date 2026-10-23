# frozen_string_literal: true

# Konfigurace QES (SPEC § 11) + redakce citlivých parametrů v logu (SPEC § 7.9).
Rails.application.config.filter_parameters += %i[token signature data_to_sign certificate pin qpin]

Rails.application.config.after_initialize do
  enabled = ActiveModel::Type::Boolean.new.cast(ENV.fetch('QES_ENABLED', 'false'))
  interval = ENV.fetch('QES_EXPIRY_JOB_INTERVAL', '60').to_i

  Qes::ExpireSessionsJob.perform_in(0) if enabled && !Rails.env.test? && interval.positive?
rescue StandardError => e
  Rails.logger.warn("[qes] could not schedule expire job: #{e.class}")
end
