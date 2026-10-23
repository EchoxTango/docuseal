# frozen_string_literal: true

require 'rails_helper'

# PAdES-LTA (SPEC § 7.4 a § 7.6): podpis appky + DSS s CRL + dokumentový
# timestamp. Ověřuje tok a strukturu; samotný DigiCert token (TSTInfo v eContent,
# `OpenSSL::PKCS7#data` nil) testuje `validator_spec`.
RSpec.describe 'QES PAdES-LTA' do
  before { QesHelpers.configure! }

  let(:submitter) { QesHelpers.build_qes_submitter }
  let(:field) { submitter.submission.template_fields.find { |f| f['type'] == 'qes' } }
  let(:pkcs) { QesHelpers.pkcs12 }

  it 'adds DSS and DocTS and validates as intact, trusted and fully covered' do
    QesHelpers.with_crl_server do
      tbs_pdf = Qes::TbsDocument.build(submitter, field)
      data = Qes::TbsDocument.signed_data(StringIO.new(tbs_pdf), Qes::TbsDocument.byte_range(tbs_pdf))
      prepared = Qes::CmsBuilder.prepare(data:, certificate: pkcs.certificate, chain: pkcs.ca_certs)
      signature = pkcs.key.sign(OpenSSL::Digest.new('SHA256'), prepared[:signed_attrs_der])
      cms_der = Qes::CmsBuilder.complete(data:, signed_attrs_der: prepared[:signed_attrs_der],
                                            signature:, certificate: pkcs.certificate, chain: pkcs.ca_certs)
      signed_pdf = Qes::Embed.call(tbs_pdf, cms_der)

      crls = Qes::Ltv.collect_revocation_data(pkcs.certificate, chain: pkcs.ca_certs)
      dss_pdf = Qes::Dss.apply(
        signed_pdf,
        crls: crls.map(&:to_der),
        certs: [pkcs.certificate.to_der],
        signature_contents: HexaPDF::Document.new(io: StringIO.new(signed_pdf)).signatures.to_a.last[:Contents].to_s
      )

      token = File.binread(QesHelpers::TEST_DIR.join('fixtures', 'digicert-token.der'))
      allow_any_instance_of(Qes::DocTimestamp::Handler).to receive(:sign).and_return(token)
      allow(Qes::Validator).to receive(:verify_timestamp).and_return(true)
      final_pdf, state = Qes::DocTimestamp.apply(dss_pdf, tsa_url: 'http://tsa.test')

      expect(state).to eq('applied')

      report = Qes::Validator.call(final_pdf, trust_roots: QesHelpers.trust_roots)
      sub_filters = report[:signatures].map { |s| s[:sub_filter] }

      expect(report[:intact]).to be true
      expect(report[:trusted]).to be true
      expect(report[:ok]).to be true
      expect(sub_filters).to include('ETSI.CAdES.detached', 'ETSI.RFC3161')
    end
  end
end
