# frozen_string_literal: true

require "net/ssh"

class Prog::Vm::GithubRunner < Prog::Base
  subject_is :github_workflow_job

  semaphore :destroy

  def self.assemble(installation, repository_name:, job_id:, job_name:, workflow_id:, workflow_name:, labels:)
    ssh_key = SshKey.generate

    DB.transaction do
      vm_st = Prog::Vm::Nexus.assemble(
        ssh_key.public_key,
        installation.project.id,
        name: "job-#{job_id}",
        size: "standard-2",
        location: "hetzner-hel1",
        boot_image: "github-ubuntu-2204",
        storage_size_gib: 86,
        enable_ip4: true
      )

      Sshable.create(
        unix_user: "ubi",
        host: "temp_#{vm_st.id}",
        raw_private_key_1: ssh_key.keypair
      ) { _1.id = vm_st.id }

      job = GithubWorkflowJob.create_with_id(
        installation_id: installation.id,
        repository_name: repository_name,
        job_id: job_id,
        job_name: job_name,
        status: "queued",
        labels: labels.join(","),
        workflow_name: workflow_name,
        workflow_id: workflow_id,
        vm_id: vm_st.id
      )

      Strand.create(prog: "Vm::GithubRunner", label: "start") { _1.id = job.id }
    end
  end

  def vm
    @vm ||= Vm[github_workflow_job.vm_id]
  end

  def github_client
    @github_client ||= Github.installation_client(github_workflow_job.installation.installation_id)
  end

  def before_run
    when_destroy_set? do
      if strand.label != "destroy"
        hop_destroy
      end
    end
  end

  label def start
    register_deadline(:wait, 10 * 60)

    hop_wait_vm
  end

  label def wait_vm
    nap 5 unless vm.strand.label == "wait"
    vm.sshable.update(host: vm.ephemeral_net4 || vm.ephemeral_net6&.nth(2))
    hop_install_actions_runner
  end

  label def install_actions_runner
    vm.sshable.cmd("curl -o actions-runner-linux-x64-2.308.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.308.0/actions-runner-linux-x64-2.308.0.tar.gz")
    vm.sshable.cmd("echo '9f994158d49c5af39f57a65bf1438cbae4968aec1e4fec132dd7992ad57c74fa  actions-runner-linux-x64-2.308.0.tar.gz' | shasum -a 256 -c")
    vm.sshable.cmd("tar xzf ./actions-runner-linux-x64-2.308.0.tar.gz")

    hop_register_runner
  end

  label def register_runner
    response = github_client.post("/repos/#{github_workflow_job.repository_name}/actions/runners/registration-token")

    token = response[:token]
    url = "https://github.com/#{github_workflow_job.repository_name}"
    name = "ubicloud-#{vm.ubid}"
    labels = ["ubicloud", "ubicloud-#{vm.display_size}", "ubicloud-#{vm.location}"].join(",")
    vm.sshable.cmd(<<CMD)
./config.sh \
  --url #{url.shellescape} \
  --token #{token.shellescape} \
  --name #{name.shellescape} \
  --labels #{labels.shellescape} \
  --no-default-labels \
  --unattended \
  --ephemeral
CMD
    vm.sshable.cmd("sudo ./svc.sh install && sudo ./svc.sh start && sudo ./svc.sh status")

    hop_wait
  end

  label def wait
    nap 30
  end

  label def destroy
    decr_destroy

    vm.sshable.cmd("sudo ./svc.sh stop && sudo ./svc.sh uninstall")

    response = github_client.post("/repos/#{github_workflow_job.repository_name}/actions/runners/remove-token")
    token = response[:token]
    vm.sshable.cmd("./config.sh remove --token #{token.shellescape}")

    vm.private_subnets.each { _1.incr_destroy }
    vm.incr_destroy
    Sshable[vm_id].destroy

    pop "github runner deleted"
  end
end
