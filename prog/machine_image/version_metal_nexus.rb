# frozen_string_literal: true

class Prog::MachineImage::VersionMetalNexus < Prog::Base
  subject_is :machine_image_version_metal

  semaphore :destroy

  def self.assemble_from_vm(machine_image, version, source_vm, store,
    destroy_source_after: false, set_as_latest: true)
    fail MachineImageError, "Source VM arch (#{source_vm.arch}) does not match machine image arch (#{machine_image.arch})" unless source_vm.arch == machine_image.arch
    fail MachineImageError, "Source VM must be a metal VM" unless source_vm.vm_host
    fail MachineImageError, "Source VM must have only one storage volume" unless source_vm.vm_storage_volumes.count == 1
    fail MachineImageError, "Source VM must be stopped" unless source_vm.display_state == "stopped"

    sv = source_vm.vm_storage_volumes.first
    fail MachineImageError, "Source VM's storage volume doesn't support machine images" unless sv.track_written
    fail MachineImageError, "Source VM's storage volume must be encrypted" unless sv.key_encryption_key_1
    fail MachineImageError, "Source VM's storage volume is larger than #{Config.machine_image_max_size_gib} GiB" if sv.size_gib > Config.machine_image_max_size_gib

    create_strand(machine_image, version, store, "archive_from_vm",
      actual_size_mib: source_vm.storage_size_gib * 1024,
      frame: {
        "source_vm_id" => source_vm.id,
        "destroy_source_after" => destroy_source_after,
        "set_as_latest" => set_as_latest,
      })
  end

  def self.assemble_from_url(machine_image, version, url, sha256sum, store, set_as_latest: true)
    vbb = VhostBlockBackend
      .where(vm_host_id: VmHost.where(location_id: machine_image.location_id).select(:id))
      .where { version_code >= VhostBlockBackend::MIN_ARCHIVE_SUPPORT_VERSION }
      .order { random.function }
      .first
    fail "no vm host with archive support found in location" unless vbb

    create_strand(machine_image, version, store, "archive_from_url",
      actual_size_mib: 0,
      frame: {
        "url" => url,
        "sha256sum" => sha256sum,
        "vm_host_id" => vbb.vm_host_id,
        "vhost_block_backend_version" => vbb.version,
        "set_as_latest" => set_as_latest,
      })
  end

  def self.create_strand(machine_image, version, store, label, actual_size_mib:, frame:)
    DB.transaction do
      miv = MachineImageVersion.create(machine_image_id: machine_image.id, version:, actual_size_mib:)
      archive_kek = StorageKeyEncryptionKey.create_random(auth_data: "machine_image_version_#{miv.ubid}_#{miv.version}")
      MachineImageVersionMetal.create_with_id(miv,
        status: "creating",
        archive_kek_id: archive_kek.id,
        store_id: store.id,
        store_prefix: "#{machine_image.project.ubid}/#{machine_image.ubid}/#{miv.version}")

      Strand.create_with_id(miv,
        prog: "MachineImage::VersionMetalNexus",
        label:,
        stack: [frame])
    end
  end

  # The archive and destroy labels just spawn a child strand running
  # the single-purpose prog at its existing entry label. They contain
  # no logic of their own.
  label def archive_from_vm
    bud Prog::MachineImage::CreateVersionMetal,
      frame.slice("source_vm_id", "destroy_source_after", "set_as_latest"),
      "archive"
    hop_wait_archive
  end

  label def archive_from_url
    bud Prog::MachineImage::CreateVersionMetalFromUrl,
      frame.slice("url", "sha256sum", "vm_host_id", "vhost_block_backend_version", "set_as_latest"),
      "archive"
    hop_wait_archive
  end

  label def wait_archive
    reap(:after_archive)
  end

  # If the create child marked the metal 'failed', wipe R2 but keep the
  # DB rows (DestroyVersionMetal#update_database leaves them in place
  # when entered at status='failed'). Otherwise the archive succeeded
  # and we settle into the steady-state wait.
  label def after_archive
    if machine_image_version_metal.status == "failed"
      bud Prog::MachineImage::DestroyVersionMetal, {}, "destroy_objects"
      hop_wait_destroy
    end
    hop_wait
  end

  label def wait
    when_destroy_set? do
      hop_destroy
    end
    nap 6 * 60 * 60
  end

  label def destroy
    bud Prog::MachineImage::DestroyVersionMetal, {}, "prep_destroy"
    hop_wait_destroy
  end

  label def wait_destroy
    reap(:popped)
  end

  label def popped
    pop "Metal machine image version is destroyed"
  end
end
