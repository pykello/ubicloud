# frozen_string_literal: true

require_relative "../model"

class GithubWorkflowJob < Sequel::Model
  many_to_one :installation, key: :installation_id, class: :GithubInstallation
  many_to_one :vm

  include ResourceMethods

  GithubWorkflowJob.unrestrict_primary_key

  include SemaphoreMethods
  semaphore :destroy

  def workflow_url
    "http://github.com/#{repository_name}/actions/runs/#{workflow_id}"
  end

  def url
    "http://github.com/#{repository_name}/actions/runs/#{workflow_id}/job/#{job_id}"
  end
end
