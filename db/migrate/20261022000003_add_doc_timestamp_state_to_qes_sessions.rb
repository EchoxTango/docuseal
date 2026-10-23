# frozen_string_literal: true

class AddDocTimestampStateToQesSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :qes_sessions, :doc_timestamp_state, :string, null: false, default: 'none'
  end
end
