# frozen_string_literal: true

module Qes
  # Odkaz do appky (SPEC § 6): universal link i fallback stránka mají stejnou
  # logiku (`QES_PUBLIC_BASE_URL` + token), jen jinou cestu (M3).
  module Link
    module_function

    def call(request, path, token)
      base = Qes::Config[:public_base_url].presence || request.base_url

      "#{base.chomp('/')}#{path}?token=#{CGI.escape(token)}"
    end
  end
end
