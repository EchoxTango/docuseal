# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Qes::RevisionChanges do
  before { QesHelpers.configure! }

  def append(document)
    output = StringIO.new
    document.write(output, incremental: true, validate: false)

    output.string
  end

  it 'does not confuse a PDF name with an indirect reference sentinel' do
    signed = QesHelpers.signed_pdf
    signed_end = Qes::TbsDocument.byte_range(signed)[2] + Qes::TbsDocument.byte_range(signed)[3]
    document = HexaPDF::Document.new(io: StringIO.new(signed))
    document.pages[0][:Contents] = [:reference, 1, 0]

    expect(described_class.allowed?(append(document), signed_end)).to be false
  end

  it 'treats a NoView widget with Print as visible' do
    document = HexaPDF::Document.new
    widget = document.add({ F: 32 | 4, Rect: [0, 0, 10, 10] })

    expect(described_class.invisible_widget?(widget)).to be false
  end

  it 'detects an Info dictionary change after the signature' do
    signed = QesHelpers.signed_pdf
    signed_end = Qes::TbsDocument.byte_range(signed)[2] + Qes::TbsDocument.byte_range(signed)[3]
    document = HexaPDF::Document.new(io: StringIO.new(signed))
    document.trailer[:Info] = { Title: 'Changed after signing' }

    expect(described_class.allowed?(append(document), signed_end)).to be false
  end
end
