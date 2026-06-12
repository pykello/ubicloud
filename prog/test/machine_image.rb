# frozen_string_literal: true

class Prog::Test::MachineImage < Prog::Test::Base
  # Stable IDs so re-runs reuse the same Project / MachineImage records
  # — and therefore the same R2 prefix (<project_ubid>/<mi_ubid>/<version>/…)
  # — instead of accumulating one orphaned prefix per failed attempt.
  SERVICE_PROJECT_ID = "ab93a7a8-7e54-8a32-9a6b-3ce2ec56f70a"
  UBUNTU_NOBLE_MI_ID = "ab93a7a8-7e54-8a45-bca6-edc97640f8aa"
  LOCATION_ID = Location::HETZNER_FSN1_ID
  SUBNET_NAME = "mi-e2e"

  # Canonical's Ubuntu cloud-image release tree. The version slug (e.g.
  # "20260601") names a directory under release-…/. The matching hash
  # comes in via E2E_UBUNTU_NOBLE_SHA256SUM so we don't depend on a live
  # HTTP fetch of SHA256SUMS during the test.
  RELEASE_URL_PATTERN = "https://cloud-images.ubuntu.com/releases/noble/release-%s/ubuntu-24.04-server-cloudimg-amd64.img"

  frame_reader :version
  frame_accessor :subnet_id, :verify_vm_id

  def self.assemble(version:)
    Strand.create(
      prog: "Test::MachineImage",
      label: "start",
      stack: [{"version" => version}],
    )
  end

  label def start
    hop_bootstrap
  end

  label def bootstrap
    project = Project[SERVICE_PROJECT_ID] ||
      Project.create_with_id(SERVICE_PROJECT_ID, name: "MachineImage-E2E-Service")

    unless MachineImageStore.first(project_id: SERVICE_PROJECT_ID, location_id: LOCATION_ID)
      MachineImageStore.create(
        project_id: SERVICE_PROJECT_ID, location_id: LOCATION_ID,
        provider: "r2", region: "auto",
        endpoint: Config.e2e_machine_images_r2_endpoint,
        bucket: Config.e2e_machine_images_r2_bucket,
        access_key: Config.e2e_machine_images_r2_access_key,
        secret_key: Config.e2e_machine_images_r2_secret_key,
      )
    end

    MachineImage[UBUNTU_NOBLE_MI_ID] ||
      MachineImage.create_with_id(UBUNTU_NOBLE_MI_ID,
        name: "ubuntu-noble", arch: "x64",
        project_id: SERVICE_PROJECT_ID, location_id: LOCATION_ID)

    subnet = project.private_subnets_dataset.first(location_id: LOCATION_ID, name: SUBNET_NAME) ||
      Prog::Vnet::SubnetNexus.assemble(SERVICE_PROJECT_ID, name: SUBNET_NAME, location_id: LOCATION_ID).subject
    self.subnet_id = subnet.id

    hop_wipe_stale
  end

  label def wipe_stale
    # Recover R2 + DB from a partial prior run: any MIV at this version
    # that isn't 'ready' gets its destroy semaphore set so its
    # VersionMetalNexus strand deletes the R2 prefix and the DB rows;
    # the next bootstrap then reads as if this version had never been
    # written.
    stale = MachineImage[UBUNTU_NOBLE_MI_ID]
      .versions_dataset
      .where(version:)
      .first&.metal
    if stale && stale.status != "ready"
      stale.incr_destroy
    end

    hop_wait_wipe
  end

  label def wait_wipe
    miv = MachineImage[UBUNTU_NOBLE_MI_ID].versions_dataset.where(version:).first
    nap 5 if miv && miv.metal && miv.metal.status != "ready"

    # If we already have a ready MIV at this version, skip the URL fetch
    # entirely and go straight to verifying the read path.
    hop_assemble_verify_vm if miv && miv.metal&.status == "ready"
    hop_create_from_url
  end

  label def create_from_url
    mi = MachineImage[UBUNTU_NOBLE_MI_ID]
    store = MachineImageStore.first(project_id: SERVICE_PROJECT_ID, location_id: LOCATION_ID)
    url = RELEASE_URL_PATTERN % version
    Prog::MachineImage::VersionMetalNexus.assemble_from_url(mi, version, url,
      Config.e2e_ubuntu_noble_sha256sum, store)
    hop_wait_create
  end

  label def wait_create
    miv = MachineImage[UBUNTU_NOBLE_MI_ID].versions_dataset.where(version:).first
    fail_test("machine image archive failed") if miv&.metal&.status == "failed"
    nap 30 unless miv&.metal&.status == "ready"
    hop_assemble_verify_vm
  end

  label def assemble_verify_vm
    # @<version> forces the lookup to use this explicit MIV instead of
    # falling back to a BootImage with the same name; the MI lives in the
    # service project, which is the verify VM's project too.
    vm = Prog::Vm::Nexus.assemble_with_sshable(SERVICE_PROJECT_ID,
      sshable_unix_user: "ubi", size: "standard-2",
      private_subnet_id: subnet_id, boot_image: "ubuntu-noble@#{version}",
      enable_ip4: true).subject
    self.verify_vm_id = vm.id
    hop_wait_verify_vm
  end

  label def wait_verify_vm
    nap 10 if Vm[verify_vm_id].display_state != "running"
    hop_verify_vm
  end

  label def verify_vm
    bud Prog::Test::Vm, {"subject_id" => verify_vm_id, "first_boot" => true}
    hop_wait_verify_smoke_checks
  end

  label def wait_verify_smoke_checks
    reap(:cleanup)
  end

  label def cleanup
    Vm[verify_vm_id]&.incr_destroy
    hop_wait_cleanup
  end

  label def wait_cleanup
    nap 5 if Vm[verify_vm_id]
    hop_finish
  end

  label def finish
    pop "MachineImage E2E finished!"
  end

  label def failed
    nap 15
  end
end
