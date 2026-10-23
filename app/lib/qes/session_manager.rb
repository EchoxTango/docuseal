# frozen_string_literal: true

module Qes
  # Stavový automat QesSession (SPEC § 4.3). Každý přechod zapíše čas a stav;
  # zakázaný přechod vyhodí Qes::InvalidTransition.
  class SessionManager
    TRANSITIONS = {
      'created' => %w[prepared expired failed cancelled declined],
      'prepared' => %w[awaiting_app expired failed cancelled declined],
      'awaiting_app' => %w[app_opened expired failed cancelled declined],
      'app_opened' => %w[awaiting_signature expired failed cancelled declined],
      'awaiting_signature' => %w[signed expired failed cancelled declined],
      'signed' => %w[embedded failed expired cancelled declined],
      'embedded' => %w[validated failed expired cancelled declined],
      'validated' => %w[completed failed expired cancelled declined],
      'completed' => [],
      'expired' => [],
      'failed' => [],
      'cancelled' => [],
      'declined' => []
    }.freeze

    TERMINAL_STATES = %w[completed expired failed cancelled declined].freeze
    ACTIVE_STATES = (TRANSITIONS.keys - TERMINAL_STATES).freeze

    def self.transition!(session, to, at: Time.current, **attributes)
      from = session.state
      to = to.to_s

      unless TRANSITIONS.fetch(from, []).include?(to)
        raise InvalidTransition, "QesSession #{session.id}: #{from} -> #{to} is not allowed"
      end

      attributes[:state] = to
      attributes[:"#{to}_at"] = at if session.class.column_names.include?("#{to}_at") && attributes[:"#{to}_at"].nil?
      attributes[:completed_at] = at if to == 'completed' && attributes[:completed_at].nil?

      session.assign_attributes(attributes)
      session.save!
      session
    end

    def self.terminal?(state)
      TERMINAL_STATES.include?(state)
    end

    def self.active?(state)
      ACTIVE_STATES.include?(state)
    end
  end
end
