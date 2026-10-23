# frozen_string_literal: true

module Qes
  # Kontrola hodnoty pole `qes` (SPEC § 4.4): povolená je jen `"qes:<id>"`
  # s `completed` session téhož submittera. Bez toho by klient mohl obřad obejít.
  module ValueValidator
    VALUE_REGEXP = /\Aqes:(\d+)\z/

    module_function

    def call(values, submitter)
      Array(values).each do |key, value|
        field = Qes.template_fields(submitter.submission).find { |f| f['uuid'] == key.to_s }
        next unless field&.dig('type') == 'qes'

        validate!(value, submitter)
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
