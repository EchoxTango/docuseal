# frozen_string_literal: true

module Qes
  # Expirace neaktivních sessions (SPEC § 7.8). Fork nemá plánovač, proto se job
  # sám přeplánuje (`perform_in`); inicializér zařadí první běh při bootu.
  # Duplicitní smyčky po restartu vylučuje časové okno přes `LockEvent`.
  class ExpireSessionsJob
    include Sidekiq::Job

    LOCK_KEY = 'qes_expire_sessions'

    def perform
      QesSession.stale.find_each do |session|
        Qes::SessionManager.transition!(session, 'expired', failure_code: 'expired')
        Qes.log(session)
      rescue Qes::InvalidTransition
        nil
      end
    ensure
      # `ensure`: výjimka (např. timeout DB) nesmí zastavit smyčku expirace.
      reschedule!
    end

    def reschedule!
      interval = Qes::Config[:expiry_job_interval].to_i
      return unless interval.positive?

      last = LockEvent.where(key: LOCK_KEY).order(:id).last

      return if last && last.created_at > (interval / 2.0).seconds.ago

      LockEvent.create!(key: LOCK_KEY, event_name: :retry)
      self.class.perform_in(interval.seconds)
    end
  end
end
