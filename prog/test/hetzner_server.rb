# frozen_string_literal: true

require_relative "../../lib/util"

class Prog::Test::HetznerServer < Prog::Test::Base
  semaphore :verify_cleanup_and_destroy
  frame_reader :server_id, :setup_host?, :default_boot_images, :provider_name
  frame_accessor :hostname, :vm_host_id, :available_storage_gib

  # Stable so re-runs reuse the same MI row and therefore the same R2 prefix
  # (<project_ubid>/<mi_ubid>/<version>/…), instead of accumulating one
  # orphan prefix per run. The Project ubid comes from
  # Config.machine_images_service_project_id (also stable across runs).
  UBUNTU_NOBLE_MI_ID = "2a0309b4-3b54-8281-8497-0cf3ee783c68" # m1581gkd1vaj0gjbgswzef0y6g

  def self.assemble(vm_host_id: nil, default_boot_images: [])
    frame = if vm_host_id
      vm_host = VmHost[vm_host_id]
      {
        "vm_host_id" => vm_host.id,
        "server_id" => vm_host.provider.server_identifier,
        "hostname" => vm_host.sshable.host,
        "setup_host?" => false,
        "default_boot_images" => default_boot_images,
        "provider_name" => vm_host.provider_name,
      }
    else
      {
        "server_id" => Config.e2e_hetzner_server_id,
        "setup_host?" => true,
        "default_boot_images" => default_boot_images,
        "provider_name" => HostProvider::HETZNER_PROVIDER_NAME,
      }
    end

    if frame["server_id"].nil? || frame["server_id"].empty?
      fail "E2E_HETZNER_SERVER_ID must be a nonempty string"
    end

    Strand.create(
      prog: "Test::HetznerServer",
      label: "start",
      stack: [frame],
    )
  end

  label def start
    hop_wait_setup_host unless setup_host?
    hop_fetch_hostname
  end

  label def fetch_hostname
    self.hostname = hetzner_api.get_main_ip4

    hop_reimage
  end

  label def reimage
    hetzner_api.reimage(
      server_id,
      dist: "Ubuntu 24.04 LTS base",
    )

    hop_wait_reimage
  end

  label def wait_reimage
    begin
      Util.rootish_ssh(hostname, "root", [Config.hetzner_ssh_private_key], "echo 1")
    rescue
      nap 15
    end

    hop_setup_host
  end

  label def setup_host
    vm_host = Prog::Vm::HostNexus.assemble(
      hostname,
      provider_name: HostProvider::HETZNER_PROVIDER_NAME,
      server_identifier: server_id,
      default_boot_images:,
    ).subject
    self.vm_host_id = vm_host.id

    hop_wait_setup_host
  end

  label def wait_setup_host
    unless vm_host.strand.label == "wait"
      Clog.emit(vm_host.sshable.cmd("ls -lah /var/storage/images").strip.tr("\n", "\t")) if vm_host.strand.label == "wait_download_boot_images"
      nap 15
    end
    self.available_storage_gib = vm_host.available_storage_gib + vm_host.boot_images.sum(&:size_gib)

    hop_setup_machine_image
  end

  # Captures ubuntu-noble into the platform machine image store so the
  # downstream VmGroup test can boot from it via the Config-driven
  # service-project fallback in Vm::Nexus.assemble. Short-circuits to
  # verify_encrypted_swap when any required Config isn't set, so the
  # rest of the HetznerServer test still runs without MI infra.
  label def setup_machine_image
    hop_verify_encrypted_swap unless mi_test_enabled?

    project = Project[Config.machine_images_service_project_id] ||
      Project.create_with_id(Config.machine_images_service_project_id, name: "MachineImage-E2E-Service")

    store = MachineImageStore.first(project_id: project.id, location_id: vm_host.location_id) ||
      MachineImageStore.create(
        project_id: project.id, location_id: vm_host.location_id,
        provider: "r2", region: "auto",
        endpoint: Config.e2e_machine_images_r2_endpoint,
        bucket: Config.e2e_machine_images_r2_bucket,
        access_key: Config.e2e_machine_images_r2_access_key,
        secret_key: Config.e2e_machine_images_r2_secret_key,
      )

    mi = MachineImage[UBUNTU_NOBLE_MI_ID] ||
      MachineImage.create_with_id(UBUNTU_NOBLE_MI_ID,
        name: "ubuntu-noble", arch: vm_host.arch,
        project_id: project.id, location_id: vm_host.location_id)

    miv = mi.versions_dataset.where(version: ubuntu_noble_version).first
    if miv.nil?
      Prog::MachineImage::VersionMetalNexus.assemble_from_url(mi, ubuntu_noble_version,
        ubuntu_noble_url, ubuntu_noble_sha256, store)
    end

    hop_wait_machine_image
  end

  label def wait_machine_image
    miv = MachineImage[UBUNTU_NOBLE_MI_ID].versions_dataset.where(version: ubuntu_noble_version).first
    fail_test "ubuntu-noble machine image archive failed" if miv&.metal&.status == "failed"
    nap 30 unless miv&.metal&.status == "ready"

    hop_verify_encrypted_swap
  end

  label def verify_encrypted_swap
    sshable = vm_host.sshable
    swap_device = sshable.cmd("swapon --show=NAME --noheadings").strip
    fail_test "swap is not on a dm-crypt device: #{swap_device}" unless swap_device.start_with?("/dev/dm-")
    hop_install_integration_specs
  end

  label def install_integration_specs
    if retval&.dig("msg") == "installed rhizome"
      verify_specs_installation(installed: true)

      hop_run_integration_specs
    end

    # We shouldn't install specs by default when running Prog::Vm::HostNexus.assemble
    verify_specs_installation(installed: false) if setup_host?

    # install specs
    push Prog::InstallRhizome, {subject_id: vm_host.id, target_folder: "host", install_specs: true}
  end

  def verify_specs_installation(installed: true)
    specs_count = vm_host.sshable.cmd("find /home/rhizome -type f -name '*_spec.rb' -not -path \"/home/rhizome/vendor/*\" | wc -l")
    specs_installed = (specs_count.strip != "0")
    fail_test "verify_specs_installation(installed: #{installed}) failed" unless specs_installed == installed
  end

  label def run_integration_specs
    tmp_dir = "/var/storage/tests"
    vm_host.sshable.cmd("sudo mkdir -p :tmp_dir", tmp_dir:)
    vm_host.sshable.cmd("sudo chmod a+rw :tmp_dir", tmp_dir:)
    vm_host.sshable.cmd("sudo RUN_E2E_TESTS=1 bundle exec rspec host/e2e")
    vm_host.sshable.cmd("sudo rm -rf :tmp_dir", tmp_dir:)

    hop_wait
  end

  label def wait
    when_verify_cleanup_and_destroy_set? do
      hop_verify_cleanup
    end

    nap 15
  end

  label def verify_cleanup
    # not all tests will wait for cleanup, so we need to wait here until the
    # cleanup is done
    nap 15 unless vm_host.vms.empty?

    hop_verify_vm_dir_purged
  end

  label def verify_vm_dir_purged
    sshable = vm_host.sshable
    vm_dir_content = sshable.cmd("sudo ls -1 /vm").split("\n")
    fail_test "VM directory not empty: #{vm_dir_content}" unless vm_dir_content.empty?
    hop_verify_storage_files_purged
  end

  label def verify_storage_files_purged
    sshable = vm_host.sshable

    vm_disks = sshable.cmd("sudo ls -1 /var/storage").split("\n").reject { ["vhost", "images"].include? it }
    fail_test "VM disks not empty: #{vm_disks}" unless vm_disks.empty?

    vhost_dir_content = sshable.cmd("sudo ls -1 /var/storage/vhost").split("\n")
    fail_test "vhost directory not empty: #{vhost_dir_content}" unless vhost_dir_content.empty?
    hop_verify_resources_reclaimed
  end

  label def verify_resources_reclaimed
    fail_test "used_cores is expected to be zero, actual: #{vm_host.used_cores}" unless vm_host.used_cores.zero?
    fail_test "used_hugepages_1g is expected to be zero, actual: #{vm_host.used_hugepages_1g}" unless vm_host.used_hugepages_1g.zero?
    reclaimed_storage_gib = vm_host.available_storage_gib + vm_host.boot_images.sum(&:size_gib)
    fail_test "available_storage_gib was not reclaimed as expected: #{available_storage_gib}, actual: #{reclaimed_storage_gib}" unless available_storage_gib == reclaimed_storage_gib

    hop_destroy_vm_host
  end

  label def destroy_vm_host
    # don't destroy the vm_host if we didn't set it up.
    hop_finish unless setup_host?

    vm_host.incr_destroy

    hop_wait_vm_host_destroyed
  end

  label def wait_vm_host_destroyed
    if vm_host
      Clog.emit("Waiting vm host to be destroyed")
      nap 10
    end

    hop_finish
  end

  label def finish
    pop "HetznerServer tests finished!"
  end

  label def failed
    nap 15
  end

  def hetzner_api
    @hetzner_api ||= Hosting::HetznerApis.new(
      HostProvider.new do |hp|
        hp.server_identifier = server_id
        hp.provider_name = HostProvider::HETZNER_PROVIDER_NAME
        hp.id = vm_host_id
      end,
    )
  end

  def vm_host
    @vm_host ||= VmHost[vm_host_id]
  end

  # Whether to capture a ubuntu-noble MI as part of the host setup.
  # Requires both an R2 store config (so the archive has somewhere to land)
  # and a service-project id (so Vm::Nexus.assemble's
  # machine_images_service_project_id fallback can find the MI when
  # downstream tests boot VMs with boot_image: "ubuntu-noble").
  def mi_test_enabled?
    Config.machine_images_service_project_id &&
      Config.e2e_machine_images_r2_endpoint &&
      Config.e2e_machine_images_r2_bucket &&
      Config.e2e_machine_images_r2_access_key &&
      Config.e2e_machine_images_r2_secret_key
  end

  def ubuntu_noble_versions
    Prog::DownloadBootImage::BOOT_IMAGE_SHA256.fetch("ubuntu-noble").fetch(vm_host.arch)
  end

  def ubuntu_noble_version
    @ubuntu_noble_version ||= ubuntu_noble_versions.keys.max
  end

  def ubuntu_noble_sha256
    ubuntu_noble_versions.fetch(ubuntu_noble_version)
  end

  def ubuntu_noble_url
    arch = vm_host.render_arch(arm64: "arm64", x64: "amd64")
    "https://cloud-images.ubuntu.com/releases/noble/release-#{ubuntu_noble_version}/ubuntu-24.04-server-cloudimg-#{arch}.img"
  end
end
