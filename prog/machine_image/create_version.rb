# frozen_string_literal: true

require "aws-sdk-s3"
require "json"

class Prog::MachineImage::CreateVersion < Prog::Base
  subject_is :machine_image_version

  def self.assemble(machine_image, version, source_vm, destroy_source_after: false)
    fail "source vm must have only one storage volume" unless source_vm.vm_storage_volumes.count == 1
    fail "source vm must be stopped" unless source_vm.display_state == "stopped"

    sv = source_vm.vm_storage_volumes.first
    fail "source vm's vhost block backend must support archive" unless sv.vhost_block_backend&.supports_archive?

    store = MachineImageStore.first(
      project_id: machine_image.project_id,
      location_id: machine_image.location_id
    ) || fail("no machine image store found for project #{machine_image.project_id} at location #{machine_image.location_id}")

    archive_kek = StorageKeyEncryptionKey.create_random(auth_data: "machine_image_version_#{machine_image.ubid}_#{version}")
    store_prefix = "#{machine_image.project.ubid}/#{machine_image.ubid}/#{version}"

    mi_version = MachineImageVersion.create(
      machine_image_id: machine_image.id,
      version:,
      enabled: false,
      actual_size_mib: sv.size_gib * 1024
    )

    MachineImageVersionMetal.create_with_id(mi_version,
      archive_kek_id: archive_kek.id,
      store_id: store.id,
      store_prefix:)

    Strand.create(
      prog: "MachineImage::CreateVersion",
      label: "archive",
      stack: [{
        "subject_id" => mi_version.id,
        "source_vm_id" => source_vm.id,
        "destroy_source_after" => destroy_source_after
      }]
    ) { it.id = mi_version.id }
  end

  label def archive
    register_deadline(nil, 15 * 60)

    source_vm = Vm[frame["source_vm_id"]]
    sv = source_vm.vm_storage_volumes.first
    daemon_name = "archive_#{machine_image_version.ubid}"
    host = source_vm.vm_host
    case host.sshable.cmd("common/bin/daemonizer --check :daemon_name", daemon_name:)
    when "Succeeded"
      host.sshable.cmd("common/bin/daemonizer --clean :daemon_name", daemon_name:)
      hop_finish
    when "Failed", "NotStarted"
      host.sshable.cmd(
        "common/bin/daemonizer 'sudo host/bin/archive-storage-volume :vm_name :device :disk_index :vhost_block_backend_version' :daemon_name",
        daemon_name:,
        vm_name: source_vm.inhost_name,
        device: sv.storage_device.name,
        disk_index: sv.disk_index,
        vhost_block_backend_version: sv.vhost_block_backend.version,
        stdin: archive_params_json
      )
    end

    nap 30
  end

  label def finish
    machine_image_version.machine_image.update(
      latest_version_id: machine_image_version.id
    )
    machine_image_version.update(enabled: true)
    machine_image_version.metal.update(archive_size_mib: archive_size_bytes / 1024 / 1024)
    if frame["destroy_source_after"]
      source_vm = Vm[frame["source_vm_id"]]
      source_vm.incr_destroy
    end
    pop "Machine image version #{machine_image_version.version} is created and enabled"
  end

  def archive_params_json
    source_vm = Vm[frame["source_vm_id"]]
    sv = source_vm.vm_storage_volumes.first
    metal = machine_image_version.metal
    store = metal.store

    {
      kek: sv.key_encryption_key_1.secret_key_material_hash,
      target_conf: {
        endpoint: store.endpoint,
        region: store.region,
        bucket: store.bucket,
        prefix: metal.store_prefix,
        access_key_id: store.access_key,
        secret_access_key: store.secret_key,
        archive_kek: metal.archive_kek.secret_key_material_hash
      }
    }.to_json
  end

  def archive_size_bytes
    metal = machine_image_version.metal
    store = metal.store

    s3 = Aws::S3::Client.new(
      region: store.region,
      endpoint: store.endpoint,
      access_key_id: store.access_key,
      secret_access_key: store.secret_key
    )

    total = 0
    s3.list_objects_v2(bucket: store.bucket, prefix: metal.store_prefix).each do |page|
      total += page.contents.sum(&:size)
    end
    total
  end
end
