# frozen_string_literal: true

require "json"

class Prog::MachineImage::CopyVersionMetal < Prog::Base
  subject_is :machine_image_version_metal

  def self.assemble(source_machine_image_version_metal, target_machine_image, target_store, set_as_latest: true)
    fail "source machine image version is not enabled" unless source_machine_image_version_metal.enabled

    source_miv = source_machine_image_version_metal.machine_image_version
    fail "target store is not in the same location as target machine image" if target_store.location_id != target_machine_image.location_id

    if MachineImageVersion.where(machine_image_id: target_machine_image.id, version: source_miv.version).any?
      fail "target machine image already has version #{source_miv.version}"
    end

    vm_host = VmHost
      .where(location_id: target_machine_image.location_id, allocation_state: "accepting")
      .order { random.function }
      .first
    fail "no vm host found in target location" unless vm_host

    DB.transaction do
      target_miv = MachineImageVersion.create(
        machine_image_id: target_machine_image.id,
        version: source_miv.version,
        actual_size_mib: source_miv.actual_size_mib,
      )

      # The archive bytes in the source store are encrypted with the source
      # archive_kek. To copy the bytes as-is to the target store, the target
      # metal must reference a KEK with identical key material and auth_data.
      # We create a new row (rather than sharing the id) so destroying either
      # metal cleans up its own KEK independently.
      source_kek = source_machine_image_version_metal.archive_kek
      target_archive_kek = StorageKeyEncryptionKey.create(
        algorithm: source_kek.algorithm,
        key: source_kek.key,
        init_vector: source_kek.init_vector,
        auth_data: source_kek.auth_data,
      )

      MachineImageVersionMetal.create_with_id(target_miv,
        enabled: false,
        archive_kek_id: target_archive_kek.id,
        store_id: target_store.id,
        store_prefix: "#{target_machine_image.project.ubid}/#{target_machine_image.ubid}/#{source_miv.version}")

      Strand.create_with_id(target_miv,
        prog: "MachineImage::CopyVersionMetal",
        label: "copy",
        stack: [{
          "source_machine_image_version_metal_id" => source_machine_image_version_metal.id,
          "vm_host_id" => vm_host.id,
          "set_as_latest" => set_as_latest,
        }])
    end
  end

  label def copy
    register_deadline(nil, [source_machine_image_version_metal.archive_size_mib.to_i / 5, 3600].max)

    unit_name = "copy_#{machine_image_version_metal.ubid}"
    sshable = vm_host.sshable

    status = sshable.d_check(unit_name)
    case status
    when "Succeeded"
      stats_json = sshable.cmd("cat :stats_path", stats_path: stats_file_path)
      stats = JSON.parse(stats_json)
      update_stack("total_bytes" => stats["total_bytes"])
      sshable.d_clean(unit_name)
      hop_finish
    when "Failed"
      sshable.d_restart(unit_name)
      nap 60
    when "NotStarted"
      sshable.d_run(unit_name,
        "sudo", "host/bin/copy-archive", stats_file_path,
        stdin: copy_params_json, log: false)
      nap 30
    when "InProgress"
      nap 30
    else
      Clog.emit("Unexpected daemonizer2 status: #{status}")
      nap 60
    end
  end

  label def finish
    vm_host.sshable.cmd("sudo rm -f :stats_path", stats_path: stats_file_path)

    machine_image_version_metal.update(
      enabled: true,
      archive_size_mib: source_machine_image_version_metal.archive_size_mib,
    )

    if frame["set_as_latest"]
      machine_image_version_metal.machine_image_version.machine_image.update(
        latest_version_id: machine_image_version_metal.id,
      )
    end

    pop "Metal machine image version is copied and enabled"
  end

  def copy_params_json
    {
      source_conf: store_conf(source_store, source_machine_image_version_metal.store_prefix),
      target_conf: store_conf(target_store, machine_image_version_metal.store_prefix),
    }.to_json
  end

  def store_conf(store, prefix)
    {
      bucket: store.bucket,
      prefix: prefix,
      region: store.region,
      endpoint: store.endpoint,
      access_key_id: store.access_key,
      secret_access_key: store.secret_key,
    }
  end

  def stats_file_path
    "/tmp/copy_stats_#{machine_image_version_metal.ubid}.json"
  end

  def vm_host
    @vm_host ||= VmHost[frame["vm_host_id"]]
  end

  def source_machine_image_version_metal
    @source_machine_image_version_metal ||= MachineImageVersionMetal[frame["source_machine_image_version_metal_id"]]
  end

  def source_store
    @source_store ||= source_machine_image_version_metal.store
  end

  def target_store
    @target_store ||= machine_image_version_metal.store
  end
end
