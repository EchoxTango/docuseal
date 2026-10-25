# frozen_string_literal: true

module Qes
  # Compare the reachable PDF object graphs, retaining reference identities and
  # stream bytes. DSS data and *new* authenticated DocTS fields/widgets are the
  # only exclusions. In particular, a timestamp never authenticates page edits.
  module RevisionChanges
    module_function

    def allowed?(bytes, signed_end, timestamp_ranges: [])
      return true if signed_end == bytes.bytesize
      return false unless signed_end.positive? && signed_end < bytes.bytesize
      return false unless bytes.byteslice(signed_end..).strip.end_with?('%%EOF')

      before = HexaPDF::Document.new(io: StringIO.new(bytes.byteslice(0, signed_end)))
      after = HexaPDF::Document.new(io: StringIO.new(bytes))
      ignored = timestamp_fields(after, before, timestamp_ranges, bytes:)

      # The DocTS handler upgrades the catalog to PDF 2.0.
      version_upgrade = ignored.any? && after.catalog[:Version] == :'2.0'
      before.catalog.delete(:Version) if version_upgrade
      after.catalog.delete(:Version) if version_upgrade
      snapshot(before) == snapshot(after, ignored:)
    rescue StandardError => e
      Rails.logger.warn("[qes] revision comparison failed: #{e.class}")
      false
    end

    def timestamp_fields(document, before, ranges, bytes:)
      ignored = Set.new
      revisions = {}
      document.acro_form&.each_field do |field|
        next unless field[:FT] == :Sig && field[:V]&.[](:SubFilter) == :'ETSI.RFC3161'
        range = field[:V][:ByteRange]&.value
        next unless ranges.include?(range)
        next unless new_object?(field, before)
        # Actions on a field are not timestamp evidence.
        next unless (field.value.keys - %i[FT V T TU TM Ff Kids Type Subtype Rect P F AP AS MK BS Border]).empty?

        widgets = (field[:Kids]&.to_a || []).map { |widget| document.deref(widget) }
        next unless widgets.all? do |widget|
          new_object?(widget, before) && widget[:Subtype] == :Widget &&
            (widget.value.keys - %i[Type Subtype Rect P Parent F AP AS MK BS Border]).empty?
        end
        # A later field must not borrow an older token's ByteRange. Its entire
        # field/widget/appearance graph must already exist in the stamped revision.
        revision = revisions[range] ||= HexaPDF::Document.new(
          io: StringIO.new(bytes.byteslice(0, range[2] + range[3]))
        )
        original = revision.object(HexaPDF::Reference.new(field.oid, field.gen))
        next unless original && field_snapshot(document, field) == field_snapshot(revision, original)

        ignored << [field.oid, field.gen]
        widgets.each { |widget| ignored << [widget.oid, widget.gen] }
      end
      ignored
    end

    def field_snapshot(document, field)
      # Page contents and annotation lists are checked by the main comparison;
      # stop at /P so a subsequent, legitimate DocTS widget doesn't change this field.
      objects = document.pages.each_with_object({}) { |page, result| result[[page.oid, page.gen]] = :page }
      root = normalize(field, document, objects, Set.new)
      [root, objects]
    end

    def new_object?(object, before)
      return false unless object.indirect?

      original = before.object(HexaPDF::Reference.new(object.oid, object.gen))
      original.nil? || original.null?
    end

    def snapshot(document, ignored: Set.new)
      objects = {}
      root = normalize(document.catalog, document, objects, ignored, :catalog)
      [root, objects]
    end

    def normalize(value, document, objects, ignored, context = nil)
      value = document.object(value) if value.is_a?(HexaPDF::Reference)
      if value.is_a?(HexaPDF::Object)
        if value.indirect?
          key = [value.oid, value.gen]
          return [:reference, *key] if objects.key?(key)

          objects[key] = nil # Break page/parent and widget/field cycles.
          objects[key] = normalize_object(value, document, objects, ignored, context)
          return [:reference, *key]
        end

        return normalize_object(value, document, objects, ignored, context)
      end

      case value
      when Hash
        value.each_with_object({}) do |(key, item), result|
          next if context == :catalog && key == :DSS

          child_context = if context == :catalog && key == :AcroForm
                            :form
                          elsif (context == :form && key == :Fields) ||
                                (value[:Type] == :Page && key == :Annots)
                            :fields
                          end
          # A writer may introduce an indirect Annots array for the new widget.
          if key == :Annots && value[:Type] == :Page
            annotations = document.deref(item)
            annotations = annotations.value if annotations.is_a?(HexaPDF::Object)
            next if annotations.is_a?(Array) && annotations.all? do |annotation|
              annotation.respond_to?(:oid) && ignored.include?([annotation.oid, annotation.gen])
            end
          end
          normalized = normalize(item, document, objects, ignored, child_context)

          result[key] = normalized
        end
      when Array
        value.filter_map do |item|
          if context == :fields && item.respond_to?(:oid) && ignored.include?([item.oid, item.gen])
            next
          end

          # Preserve PDF nulls in ordinary arrays (filter_map would drop nil).
          [normalize(item, document, objects, ignored)]
        end.flatten(1)
      else
        value
      end
    end

    def normalize_object(object, document, objects, ignored, context)
      value = normalize(object.value, document, objects, ignored, context)
      object.is_a?(HexaPDF::Stream) ? [value, object.stream] : value
    end
  end
end
