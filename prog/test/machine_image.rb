# frozen_string_literal: true

class Prog::Test::MachineImage < Prog::Test::Base
  # Stable IDs so re-runs reuse the same Project / MachineImage records
  # — and therefore the same R2 prefix (<project_ubid>/<mi_ubid>/<version>/…)
  # — instead of accumulating one orphaned prefix per failed attempt.
  SERVICE_PROJECT_ID = "ab93a7a8-7e54-8a32-9a6b-3ce2ec56f70a"
  UBUNTU_NOBLE_MI_ID = "ab93a7a8-7e54-8a45-bca6-edc97640f8aa"
  LOCATION_ID = Location::HETZNER_FSN1_ID

  frame_reader :version

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
    Project[SERVICE_PROJECT_ID] ||
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

    pop "MachineImage E2E bootstrap finished!"
  end

  label def failed
    nap 15
  end
end
