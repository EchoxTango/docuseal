# frozen_string_literal: true

module Qes
  # Rate limiting token endpointů (SPEC § 5): max 60 požadavků / 5 min / IP
  # a max 10 neúspěšných pokusů o token / 5 min / IP (Rails.cache).
  module RateLimiter
    IP_LIMIT = 60
    IP_WINDOW = 5.minutes
    FAILURE_LIMIT = 10
    FAILURE_WINDOW = 5.minutes

    module_function

    def check!(ip, token: nil)
      increment("qes:rate:ip:#{ip}", IP_WINDOW, IP_LIMIT)
      increment("qes:rate:token:#{Digest::SHA256.hexdigest(token.to_s)}", IP_WINDOW, IP_LIMIT) if token.present?

      if failure_count(ip) >= FAILURE_LIMIT
        raise ClientError.new(:rate_limited, 'Too many failed attempts')
      end
    end

    def record_failure!(ip)
      increment("qes:rate:fail:#{ip}", FAILURE_WINDOW, FAILURE_LIMIT)
    end

    def failure_count(ip)
      Rails.cache.read("qes:rate:fail:#{ip}").to_i
    end

    # `read` + `write` není atomické; souběh dvou requestů limit obejde.
    # Pro rate limiting je to přijatelné (M20) — limit je ochrana, ne garance.
    def increment(key, window, limit)
      count = Rails.cache.read(key).to_i + 1
      Rails.cache.write(key, count, expires_in: window)

      raise ClientError.new(:rate_limited, 'Too many requests') if count > limit

      count
    end
  end
end
