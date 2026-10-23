# frozen_string_literal: true

class CreateQesSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :qes_sessions do |t|
      t.bigint :account_id, null: false
      t.bigint :submission_id, null: false
      t.bigint :submitter_id, null: false
      t.string :field_uuid, null: false
      t.string :provider, null: false, default: 'mobile_app'
      t.string :state, null: false, default: 'created'
      t.string :token_digest
      t.string :hash_algorithm, null: false, default: 'sha256'
      t.string :signature_algorithm, null: false, default: 'rsa_pkcs1v15'
      t.string :level
      t.string :key_location
      t.text :certificate_info
      t.text :certificate_chain
      t.binary :signed_attrs_der
      t.binary :signature
      t.string :document_digest
      t.string :signed_pdf_sha256
      t.string :final_pdf_sha256
      t.text :validation_report
      t.string :seal_state, null: false, default: 'none'
      t.text :app_metadata
      t.datetime :expires_at
      t.datetime :prepared_at
      t.datetime :app_opened_at
      t.datetime :signed_at
      t.datetime :embedded_at
      t.datetime :validated_at
      t.datetime :completed_at
      t.datetime :failed_at
      t.string :failure_code
      t.string :failure_message
      t.datetime :created_at, null: false
      t.datetime :updated_at, null: false
    end

    add_index :qes_sessions, :account_id
    add_index :qes_sessions, :submission_id
    add_index :qes_sessions, %i[submitter_id state]
    add_index :qes_sessions, :expires_at
    add_index :qes_sessions, :token_digest, unique: true

    add_foreign_key :qes_sessions, :accounts
    add_foreign_key :qes_sessions, :submissions
    add_foreign_key :qes_sessions, :submitters
  end
end
