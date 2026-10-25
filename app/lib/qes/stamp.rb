# frozen_string_literal: true

module Qes
  # Viditelná pečeť podepisujícího (SPEC § 7.1): kreslí se do TBS PDF před
  # podpisem, takže ji podpis kryje a zůstává INTACT (DESIGN § 12 #8 — pole
  # `qes` bylo neviditelné, uživatel chce pečeť vidět).
  module Stamp
    MIN_WIDTH = 150
    MIN_HEIGHT = 44

    module_function

    def draw(pdf, submitter, field, offsets = {})
      area = field&.dig('areas', 0)
      return if area.present? && offsets.present? && !offsets.key?(area['attachment_uuid'])

      page_index =
        if area.present?
          area['page'].to_i + offsets.fetch(area['attachment_uuid'], 0)
        else
          pdf.pages.size - 1
        end
      page = pdf.pages[[page_index, pdf.pages.size - 1].min]
      return if page.nil?

      width = page.box.width
      height = page.box.height
      x = area.present? ? area['x'].to_f * width : 36.0
      top = area.present? ? area['y'].to_f * height : height - 36.0 - MIN_HEIGHT
      w = area.present? ? area['w'].to_f * width : MIN_WIDTH
      h = area.present? ? area['h'].to_f * height : MIN_HEIGHT

      w = [[w, MIN_WIDTH].max, [width - x, 10].max].min
      h = [[h, MIN_HEIGHT].max, [height - top, 10].max].min
      y = [height - top - h, 0].max

      lines = stamp_lines(submitter)
      return if lines.empty?

      font = pdf.fonts.add(Submissions::GenerateResultAttachments::FONT_NAME)
      font_size = (h * 0.22).clamp(4, 9).to_f
      padding = [h * 0.10, 2.5].max
      canvas = page.canvas(type: :overlay)

      canvas.save_graphics_state do
        canvas.line_width(0.7)
        canvas.stroke_color(0x29, 0x13, 0x34)
        canvas.fill_color(0xF6, 0xF1, 0xF9)
        canvas.rectangle(x + 1, y + 1, [w - 2, 1].max, [h - 2, 1].max, radius: 2).fill_stroke
      end

      canvas.fill_color(0x29, 0x13, 0x34)
      canvas.font(font, size: font_size)

      line_height = font_size * 1.3
      lines.each_with_index do |line, index|
        baseline = y + h - padding - font_size - (line_height * index)
        next if baseline < y

        canvas.text(fit_text(font, line, font_size, w - (2 * padding)), at: [x + padding, baseline])
      end
    end

    def stamp_lines(submitter)
      locale = submitter.account.locale

      I18n.with_locale(locale) do
        [
          I18n.t('qes.stamp.title'),
          submitter.name.to_s,
          I18n.l(Time.current.to_date, format: :long, locale: locale)
        ].map(&:strip).reject(&:blank?)
      end
    end

    def fit_text(font, text, font_size, max_width)
      return text if text_width(font, text, font_size) <= max_width

      (1..text.length).reverse_each do |length|
        candidate = "#{text[0, length]}…"

        return candidate if text_width(font, candidate, font_size) <= max_width
      end

      ''
    end

    def text_width(font, text, font_size)
      HexaPDF::Layout::TextFragment.create(text, font:, font_size:).width
    end
  end
end
