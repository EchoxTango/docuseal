# frozen_string_literal: true

# Náhled uloženého ověřeného PDF (docs/16 § 4.6). Report i dokument se čtou
# z template; samotné ověření zůstává v API a tady se nic nepřepočítává.
class TemplatesQesVerificationsController < ApplicationController
  load_and_authorize_resource :template

  def show
    @report = @template.preferences&.dig(Qes::VerifiedDocuments::REPORT_KEY)
    @document = @template.schema_documents.first

    head :not_found if @report.blank? || @document.blank?
  end
end
