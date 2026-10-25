# frozen_string_literal: true

module Qes
  # Kontrola hodnoty pole `qes` (SPEC § 4.4): povolená je jen `"qes:<id>"`
  # s `completed` session téhož submittera. Bez toho by klient mohl obřad obejít.
  module ValueValidator
    VALUE_REGEXP = /\Aqes:(\d+)\z/

    module_function

    def call(values, submitter)
      validate_signed_values!(submitter.values.merge(values.to_h), submitter)

      Array(values).each do |key, value|
        field = Qes.template_fields(submitter.submission).find { |f| f['uuid'] == key.to_s }
        next unless field&.dig('type') == 'qes'

        validate!(value, submitter)
      end
    end

    # Snapshot patří ke konkrétním bajtům TBS, nikoli k pozdějším hodnotám formuláře.
    def non_qes_values(values, submitter)
      Qes.template_fields(submitter.submission).each_with_object({}) do |field, result|
        next if field['type'] == 'qes' || field['submitter_uuid'] != submitter.uuid

        result[field['uuid']] = values[field['uuid']]
      end
    end

    def validate_signed_values!(values, submitter)
      submitter.qes_sessions.completed.each do |session|
        snapshot = session.tbs_document.blob&.metadata&.fetch('qes_values', nil)
        snapshot ||= non_qes_values(submitter.values_in_database, submitter)

        next if non_qes_values(values, submitter) == snapshot &&
                non_qes_values(submitter.values, submitter) == snapshot

        raise Submitters::SubmitValues::ValidationError, 'Signed field values cannot be changed'
      end
    end

    def validate!(value, submitter)
      match = VALUE_REGEXP.match(value.to_s)

      raise Submitters::SubmitValues::ValidationError, 'Invalid qes field value' if match.nil?

      session = QesSession.find_by(id: match[1], submitter_id: submitter.id, state: 'completed')

      raise Submitters::SubmitValues::ValidationError, 'Invalid qes field value' if session.nil?
    end
  end
end
