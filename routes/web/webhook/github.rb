# frozen_string_literal: true

class CloverWeb
  hash_branch(:webhook_prefix, "github") do |r|
    r.post true do
      response.headers["Content-Type"] = "application/json"

      data = JSON.parse(r.body.read)
      case r.headers["x-github-event"]
      when "installation"
        return handle_installation(data)
      when "workflow_job"
        return handle_workflow_job(data)
      end

      return error("Unhandled event")
    rescue => e
      puts "GitHub webhook error: #{e}"
      return error(e.to_s)
    end
  end

  def error(msg)
    {error: {message: msg}}.to_json
  end

  def handle_installation(data)
    installation = GithubInstallation[installation_id: data["installation"]["id"]]
    case data["action"]
    when "deleted"
      installation.workflow_jobs_dataset.eager(:vm).all.each do |job|
        if (vm = job.vm)
          vm.private_subnets.each { _1.incr_destroy }
          vm.incr_destroy
        end
        job.destroy
      end
      installation.destroy
    end
  end

  def handle_workflow_job(data)
    unless (installation = GithubInstallation[installation_id: data["installation"]["id"]])
      return error("Unregistered installation")
    end
    unless (job = GithubWorkflowJob[job_id: data["workflow_job"]["id"]])
      unless data["action"] == "queued"
        return error("Unregistered job")
      end

      unless data["workflow_job"]["labels"].include?("ubicloud")
        return error("Unmatched label")
      end

      st = Prog::Vm::GithubRunner.assemble(
        installation,
        repository_name: data["repository"]["full_name"],
        job_id: data["workflow_job"]["id"],
        job_name: data["workflow_job"]["name"],
        workflow_id: data["workflow_job"]["run_id"],
        workflow_name: data["workflow_job"]["workflow_name"],
        labels: data["workflow_job"]["labels"]
      )
      job = GithubWorkflowJob[st.id]
      return {message: "Vm[#{job.vm.ubid}] will be created"}.to_json
    end

    job.update(status: data["workflow_job"]["conclusion"] || data["workflow_job"]["status"])

    if data["action"] == "completed" && job.vm
      job.incr_destroy
      return {message: "Vm[#{job.vm.ubid}] will be deleted"}.to_json
    end

    {message: "Job[#{job.id}] updated"}.to_json
  end
end
