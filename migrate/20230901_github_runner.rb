# frozen_string_literal: true

Sequel.migration do
  change do
    create_table(:github_installation) do
      column :id, :uuid, primary_key: true, default: nil
      column :installation_id, :bigint, null: false
      column :name, :text, collate: '"C"', null: false
      foreign_key :project_id, :project, type: :uuid
    end

    create_table(:github_workflow_job) do
      column :id, :uuid, primary_key: true, default: nil
      foreign_key :installation_id, :github_installation, type: :uuid
      column :repository_name, :text, collate: '"C"', null: false
      column :status, :text, collate: '"C"', null: false
      column :job_id, :bigint, null: false
      column :job_name, :text, collate: '"C"', null: false
      column :workflow_id, :bigint, null: false
      column :workflow_name, :text, collate: '"C"', null: false
      column :labels, :text, collate: '"C"', null: false
      column :vm_id, :uuid, null: false
    end
  end
end
