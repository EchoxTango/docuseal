# frozen_string_literal: true

module Qes
  module SigningValues
    class IncompleteFields < Qes::ClientError
      attr_reader :missing_fields

      def initialize(fields)
        @missing_fields = fields.map { |field| field['name'].presence || field['uuid'] }
        super(:fields_incomplete)
      end
    end

    module_function

    # Kontrola při startu nesmí uložit datum ani vytvářet přílohy razítek.
    def validate!(submitter)
      candidate = Submitter.find(submitter.id)
      prepare!(candidate, with_stamp: false)
      Qes::TbsDocument.document_manifest(candidate)
    end

    # Připraví hodnoty v paměti; volající je uloží společně se stavem session.
    def prepare!(submitter, with_stamp: true)
      completed_at = submitter.completed_at
      # Razítko používá čas dokončení; formulář tím ale ještě nedokončujeme.
      submitter.completed_at ||= Time.current
      submission = submitter.submission
      submission.template_fields = Qes.template_fields(submission)
      required = Set.new

      Submitters::SubmitValues.finalize_values!(submitter, required_field_uuids_acc: required,
                                                         validate_verification: false, with_stamp:)

      missing = submission.template_fields.select do |field|
        field['type'] != 'qes' && required.include?(field['uuid']) && submitter.values[field['uuid']].blank?
      end

      raise IncompleteFields, missing if missing.present?

      submitter.values
    rescue Submitters::SubmitValues::ValidationError => e
      raise Qes::ClientError.new(:values_changed, e.message)
    ensure
      submitter.completed_at = completed_at
    end
  end
end
