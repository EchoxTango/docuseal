# frozen_string_literal: true

class AddExpiredAtToQesSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :qes_sessions, :expired_at, :datetime
  end
end
