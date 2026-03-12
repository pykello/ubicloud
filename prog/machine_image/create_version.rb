# frozen_string_literal: true

require "json"

class Prog::MachineImage::CreateVersion < Prog::Base
  subject_is :machine_image_version

  def self.assemble(machine_image, version, source_vm, object_store, bucket:, destroy_source_after: false)
    fail "source vm must have only one storage volume" unless source_vm.vm_storage_volumes.count == 1
    fail "source vm must be stopped" unless source_vm.display_state == "stopped"

    sv = source_vm.vm_storage_volumes.first
    fail "source vm's vhost block backend must support archive" unless sv.vhost_block_backend&.supports_archive?

    key_encryption_key = StorageKeyEncryptionKey.create_random(auth_data: "machine_image_version_#{machine_image.ubid}_#{version}")
    s3_prefix = "#{machine_image.project.ubid}/#{machine_image.ubid}/#{version}"

    mi_version = MachineImageVersion.create(
      machine_image_id: machine_image.id,
      version:,
      enabled: false,
      actual_size_mib: sv.size_gib * 1024
    )

    MachineImageVersionMetal.create_with_id(mi_version,
      object_store_id: object_store.id,
      s3_bucket: bucket,
      s3_prefix:,
      key_encryption_key_1_id: key_encryption_key.id
    )

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

    daemon_name = "archive_#{machine_image_version.ubid}"
    host = Vm[frame["source_vm_id"]].vm_host
    case host.sshable.cmd("common/bin/daemonizer --check :daemon_name", daemon_name:)
    when "Succeeded"
      host.sshable.cmd("common/bin/daemonizer --clean :daemon_name", daemon_name:)
      hop_finish
    when "Failed", "NotStarted"
      host.sshable.cmd("common/bin/daemonizer 'sudo host/bin/archive-storage-volume' :daemon_name", daemon_name:, stdin: archive_params_json)
    end

    nap 30
  end

  label def finish
    machine_image_version.machine_image.update(
      latest_version_id: machine_image_version.id
    )
    machine_image_version.update(enabled: true)
    machine_image_version.metal.update(
      archive_size_mib: archive_size_bytes / 1024 / 1024
    )
    if frame["destroy_source_after"]
      source_vm = Vm[frame["source_vm_id"]]
      source_vm.incr_destroy
    end
    pop "Machine image version #{machine_image_version.version} is created and enabled"
  end

  def archive_params_json
    metal = machine_image_version.metal
    object_store = metal.object_store

    # We use temporary credentials for operations done in the VM hosts.
    creds = object_store.generate_temp_credentials(bucket: metal.s3_bucket)

    source_vm = Vm[frame["source_vm_id"]]
    sv = source_vm.vm_storage_volumes.first

    {
      vm_name: source_vm.inhost_name,
      device: sv.storage_device.name,
      disk_index: sv.disk_index,
      vhost_block_backend_version: sv.vhost_block_backend.version,
      kek: sv.key_encryption_key_1.secret_key_material_hash,
      target_conf: {
        endpoint: object_store.url,
        region: "auto",
        bucket: metal.s3_bucket,
        prefix: metal.s3_prefix,
        access_key_id: creds[:access_key_id],
        secret_access_key: creds[:secret_access_key],
        session_token: creds[:session_token],
        archive_kek: metal.key_encryption_key_1.secret_key_material_hash
      }
    }.to_json
  end

  def archive_size_bytes
    metal = machine_image_version.metal
    object_store = metal.object_store

    total = 0
    object_store.s3_client.list_objects_v2(bucket: metal.s3_bucket, prefix: metal.s3_prefix).each do |page|
      total += page.contents.sum(&:size)
    end
    total
  end
end
