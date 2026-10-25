# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::TbsDocument do
  before { QesHelpers.configure! }

  it 'reports invalid_pdf for a PDF without a signature byte range' do
    pdf = HexaPDF::Document.new
    pdf.pages.add
    output = StringIO.new
    pdf.write(output)

    expect { described_class.byte_range(output.string) }
      .to raise_error(Qes::ClientError) { |error| expect(error.code).to eq(:invalid_pdf) }
  end
end
