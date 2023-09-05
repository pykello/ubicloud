# frozen_string_literal: true

require_relative "../model"

class GithubInstallation < Sequel::Model
  many_to_one :project
  one_to_many :workflow_jobs, key: :installation_id, class: :GithubWorkflowJob

  include ResourceMethods

  GithubInstallation.unrestrict_primary_key
end
