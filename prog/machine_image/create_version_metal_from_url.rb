# frozen_string_literal: true

require "json"

class Prog::MachineImage::CreateVersionMetalFromUrl < Prog::Base
  subject_is :machine_image_version_metal

  def self.assemble(machine_image_version, url, sha256sum, store, set_as_latest: true)
    mi = machine_image_version.machine_image
    version = machine_image_version.version

    vbb = VhostBlockBackend.where(
      vm_host_id: VmHost.where(location_id: mi.location_id).select(:id),
    ).where { version_code >= VhostBlockBackend::MIN_ARCHIVE_SUPPORT_VERSION }
      .order(Sequel.lit("random()"))
      .first

    fail "no vm host with archive support found in location" unless vbb

    archive_kek = StorageKeyEncryptionKey.create_random(auth_data: "machine_image_version_#{machine_image_version.ubid}_#{version}")

    mi_version_metal = MachineImageVersionMetal.create_with_id(
      machine_image_version,
      enabled: false,
      archive_kek_id: archive_kek.id,
      store_id: store.id,
      store_prefix: "#{mi.project.ubid}/#{mi.ubid}/#{version}",
    )

    Strand.create_with_id(
      mi_version_metal,
      prog: "MachineImage::CreateVersionMetalFromUrl",
      label: "archive",
      stack: [{
        "subject_id" => mi_version_metal.id,
        "url" => url,
        "sha256sum" => sha256sum,
        "vm_host_id" => vbb.vm_host_id,
        "vhost_block_backend_version" => vbb.version,
        "set_as_latest" => set_as_latest,
      }],
    )
  end

  label def archive
    mi_version = machine_image_version_metal.machine_image_version
    register_deadline(nil, (mi_version.actual_size_mib || 30 * 1024) * 24 / 1024) # ~4 minutes per 10 GiB

    unit_name = "archive_#{mi_version.ubid}"
    sshable = vm_host.sshable

    status = sshable.d_check(unit_name)
    case status
    when "Succeeded"
      stats_json = sshable.cmd("cat :stats_path", stats_path: stats_file_path)
      stats = JSON.parse(stats_json)
      update_stack("archive_size_bytes" => stats["physical_size_bytes"])
      update_stack("logical_size_bytes" => stats["logical_size_bytes"])
      sshable.d_clean(unit_name)
      hop_finish
    when "Failed"
      sshable.d_restart(unit_name)
      nap 60
    when "NotStarted"
      sshable.d_run(unit_name,
        "sudo", "host/bin/archive-url", frame["url"], frame["sha256sum"], frame["vhost_block_backend_version"], stats_file_path,
        stdin: archive_params_json, log: false)
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
      archive_size_mib: (frame["archive_size_bytes"]/1048576r).ceil,
    )

    miv = machine_image_version_metal.machine_image_version
    miv.update(actual_size_mib: (frame["logical_size_bytes"]/1048576r).ceil)

    if frame["set_as_latest"]
      miv.machine_image.update(latest_version_id: miv.id)
    end

    pop "Metal machine image version is created and enabled"
  end

  def archive_params_json
    store = machine_image_version_metal.store

    {
      target_conf: {
        endpoint: store.endpoint,
        region: store.region,
        bucket: store.bucket,
        prefix: machine_image_version_metal.store_prefix,
        access_key_id: store.access_key,
        secret_access_key: store.secret_key,
        archive_kek: machine_image_version_metal.archive_kek.secret_key_material_hash,
      },
    }.to_json
  end

  def stats_file_path
    mi_version = machine_image_version_metal.machine_image_version
    "/tmp/archive_stats_#{mi_version.ubid}.json"
  end

  def vm_host
    @vm_host ||= VmHost[frame["vm_host_id"]]
  end
end
