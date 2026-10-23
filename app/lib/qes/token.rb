# frozen_string_literal: true

module Qes
  # Jednorázový token pro appku (SPEC § 5): 43 znaků urlsafe base64, v DB jen sha256.
  module Token
    module_function

    def generate
      SecureRandom.urlsafe_base64(32)
    end

    def digest(token)
      Digest::SHA256.hexdigest(token.to_s)
    end

    def find(token)
      return if token.blank?

      QesSession.find_by(token_digest: digest(token))
    end
  end
end
