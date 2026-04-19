# frozen_string_literal: true

require "aws-sdk-s3"

class Prog::MachineImage::CopyVersionMetal < Prog::Base
  subject_is :machine_image_version_metal

  def self.assemble(source_machine_image_version_metal, target_machine_image, target_store, set_as_latest: true)
    fail "source machine image version is not enabled" unless source_machine_image_version_metal.enabled

    source_miv = source_machine_image_version_metal.machine_image_version
    fail "target store is not in the same location as target machine image" if target_store.location_id != target_machine_image.location_id

    if MachineImageVersion.where(machine_image_id: target_machine_image.id, version: source_miv.version).any?
      fail "target machine image already has version #{source_miv.version}"
    end

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
        label: "copy_objects",
        stack: [{
          "source_machine_image_version_metal_id" => source_machine_image_version_metal.id,
          "set_as_latest" => set_as_latest,
        }])
    end
  end

  label def copy_objects
    register_deadline(nil, [source_machine_image_version_metal.archive_size_mib.to_i / 10, 600].max)

    list_kwargs = {
      bucket: source_store.bucket,
      prefix: source_machine_image_version_metal.store_prefix,
      max_keys: 100,
    }
    if (token = frame["continuation_token"])
      list_kwargs[:continuation_token] = token
    end

    page = source_s3_client.list_objects_v2(**list_kwargs)

    page.contents.each do |obj|
      relative_key = obj.key.delete_prefix("#{source_machine_image_version_metal.store_prefix}/")
      target_key = "#{machine_image_version_metal.store_prefix}/#{relative_key}"

      response = source_s3_client.get_object(bucket: source_store.bucket, key: obj.key)
      target_s3_client.put_object(
        bucket: target_store.bucket,
        key: target_key,
        body: response.body,
        content_length: obj.size,
      )
    end

    if page.is_truncated
      update_stack("continuation_token" => page.next_continuation_token)
      nap 0
    else
      delete_from_stack("continuation_token")
      hop_finish
    end
  end

  label def finish
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

  def source_machine_image_version_metal
    @source_machine_image_version_metal ||= MachineImageVersionMetal[frame["source_machine_image_version_metal_id"]]
  end

  def source_store
    @source_store ||= source_machine_image_version_metal.store
  end

  def target_store
    @target_store ||= machine_image_version_metal.store
  end

  def source_s3_client
    @source_s3_client ||= build_s3_client(source_store)
  end

  def target_s3_client
    @target_s3_client ||= build_s3_client(target_store)
  end

  def build_s3_client(store)
    Aws::S3::Client.new(
      access_key_id: store.access_key,
      secret_access_key: store.secret_key,
      endpoint: store.endpoint,
      region: store.region,
      force_path_style: true,
      http_open_timeout: 5,
      http_read_timeout: 60,
      retry_limit: 0,
    )
  end
end
