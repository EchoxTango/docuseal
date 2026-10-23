# frozen_string_literal: true

require 'rails_helper'

# LTV (SPEC § 7.4): CRL pro DSS slovník a URL z certifikátu se smí
# stahovat jen z allowlistu (SSRF ochrana).
RSpec.describe Qes::Ltv do
  before { QesHelpers.configure! }

  describe '.validate_url!' do
    it 'allows an explicitly allowlisted host over http (testy)' do
      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .not_to raise_error
    end

    it 'rejects a host outside the allowlist' do
      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .not_to raise_error
      expect { described_class.validate_url!(URI.parse('http://169.254.169.254/latest/meta-data/')) }
        .to raise_error(Qes::Ltv::FetchError, /not in QES_LTV_ALLOWED_HOSTS/)
    end

    it 'requires https for a public host when no allowlist is set' do
      Qes::Config[:ltv_allowed_hosts] = nil

      expect { described_class.validate_url!(URI.parse('http://example.com/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError, /https/)
    end

    it 'rejects a private address when no allowlist is set' do
      Qes::Config[:ltv_allowed_hosts] = nil

      expect { described_class.validate_url!(URI.parse('http://127.0.0.1:8765/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError)
      expect { described_class.validate_url!(URI.parse('https://127.0.0.1/root.crl')) }
        .to raise_error(Qes::Ltv::FetchError, /private address/)
      expect { described_class.validate_url!(URI.parse('https://169.254.169.254/latest/meta-data/')) }
        .to raise_error(Qes::Ltv::FetchError, /private address/)
    end

    it 'rejects unsupported schemes' do
      expect { described_class.validate_url!(URI.parse('file:///etc/passwd')) }
        .to raise_error(Qes::Ltv::FetchError, /scheme/)
    end
  end
end
