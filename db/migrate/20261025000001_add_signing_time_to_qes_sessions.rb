# frozen_string_literal: true

class AddSigningTimeToQesSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :qes_sessions, :signing_time, :datetime
  end
end
