# frozen_string_literal: true

class Serializers::Web::GithubWorkflowJob < Serializers::Base
  def self.base(job)
    {
      id: job.id,
      name: job.job_name, # FIXME: make it name
      url: job.url,
      status: job.status,
      labels: job.labels,
      repository_name: job.repository_name,
      workflow_name: job.workflow_name,
      workflow_id: job.workflow_id,
      workflow_url: job.workflow_url,
      vm: job.vm ? {
        name: job.vm.name,
        path: job.vm.path
      } : nil
    }
  end

  structure(:default) do |job|
    base(job)
  end
end
