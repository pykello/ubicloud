# frozen_string_literal: true

require_relative "vhost_block_backend"
require_relative "vhost_backend_config_v2"

# Handles vhost-backend < 0.4.0 (YAML config format).
class VhostStorageVolume < StorageVolume
  def initialize(vm_name, params)
    super
    @vhost_backend_version = params["vhost_block_backend_version"]
    @slice = params.fetch("slice_name", "system.slice")
    @stripe_sector_count_shift = Integer(params.fetch("stripe_sector_count_shift", 11))
  end

  def prep(key_wrapping_secrets)
    # Device path is intended to be created by system admin, so fail loudly if
    # it doesn't exist
    fail "Storage device directory doesn't exist: #{sp.device_path}" if !File.exist?(sp.device_path)

    FileUtils.mkdir_p storage_dir
    FileUtils.chown @vm_name, @vm_name, storage_dir
    encryption_key = setup_data_encryption_key(key_wrapping_secrets) if @encrypted

    create_empty_disk_file
    prep_vhost_backend(encryption_key, key_wrapping_secrets)
  end

  def start(key_wrapping_secrets)
    vhost_backend_start(key_wrapping_secrets)
  end

  def purge_spdk_artifacts
    service_file_path = "/etc/systemd/system/#{vhost_user_block_service}"
    stop_service_if_loaded(vhost_user_block_service)
    rm_if_exists(service_file_path)
    rm_if_exists(vhost_sock)
  end

  def vhost_user_block_service
    @vhost_user_block_service ||= "#{@vm_name}-#{@disk_index}-storage.service"
  end

  def q_vhost_user_block_service
    @q_vhost_user_block_service ||= vhost_user_block_service.shellescape
  end

  def prep_vhost_backend(encryption_key, key_wrapping_secrets)
    vhost_backend_create_config(encryption_key, key_wrapping_secrets)
    vhost_backend_create_metadata(key_wrapping_secrets) if @image_path
    vhost_backend_create_service_file
  end

  def vhost_backend_create_config(encryption_key, key_wrapping_secrets)
    config_path = sp.vhost_backend_config
    config = vhost_backend_yaml_config(encryption_key, key_wrapping_secrets)
    write_new_file(config_path, @vm_name) do |file|
      file.write(config.to_yaml)
      fsync_or_fail(file)
    end
    sync_parent_dir(config_path)
  end

  def vhost_backend_create_metadata(key_wrapping_secrets)
    vhost_backend = VhostBlockBackend.new(@vhost_backend_version)
    metadata_path = sp.vhost_backend_metadata
    config_path = sp.vhost_backend_config

    if @encrypted
      kek_stdin = vhost_backend_kek(key_wrapping_secrets).to_yaml
      kek_arg = "--kek /dev/stdin"
    else
      kek_stdin = ""
    end

    write_new_file(metadata_path, @vm_name) do |file|
      file.truncate(8 * 1024 * 1024)
    end

    r "#{vhost_backend.init_metadata_path.shellescape} -s #{@stripe_sector_count_shift}  --config #{config_path.shellescape} #{kek_arg}", stdin: kek_stdin
    sync_parent_dir(metadata_path)
  end

  def vhost_backend_create_service_file
    vhost_backend = VhostBlockBackend.new(@vhost_backend_version)
    kek_arg = "--kek #{sp.kek_pipe}" if @encrypted
    write_vhost_service_file(vhost_backend, kek_arg)
  end

  def vhost_backend_start(key_wrapping_secrets)
    # Stop the service in case this is a retry.
    r "systemctl stop #{q_vhost_user_block_service}"

    unless @encrypted
      r "systemctl start #{q_vhost_user_block_service}"
      return
    end

    begin
      kek_pipe = sp.kek_pipe
      rm_if_exists(kek_pipe)
      File.mkfifo(kek_pipe, 0o600)
      FileUtils.chown @vm_name, @vm_name, kek_pipe

      r "systemctl start #{q_vhost_user_block_service}"

      Timeout.timeout(5) do
        kek_yaml = vhost_backend_kek(key_wrapping_secrets).to_yaml
        File.write(kek_pipe, kek_yaml)
      end
    ensure
      FileUtils.rm_f(kek_pipe)
    end
  end

  private

  def vhost_backend_yaml_config(encryption_key, key_wrapping_secrets)
    config = {
      "path" => disk_file,
      "socket" => vhost_sock,
      "num_queues" => @num_queues,
      "queue_size" => @queue_size,
      "seg_size_max" => 64 * 1024,
      "seg_count_max" => 4,
      "copy_on_read" => @copy_on_read,
      "poll_queue_timeout_us" => 1000,
      "device_id" => @device_id,
      "skip_sync" => @skip_sync,
      "write_through" => write_through_device?,
      "rpc_socket_path" => sp.rpc_socket_path
    }

    if @image_path
      config["image_path"] = @image_path
      config["metadata_path"] = sp.vhost_backend_metadata
    end

    if @encrypted
      key_encryption = StorageKeyEncryption.new(key_wrapping_secrets)
      key1_wrapped_b64 = wrap_key_b64(key_encryption, encryption_key[:key])
      key2_wrapped_b64 = wrap_key_b64(key_encryption, encryption_key[:key2])
      config["encryption_key"] = [key1_wrapped_b64, key2_wrapped_b64]
    end

    if @cpus
      config["cpus"] = @cpus
      config["num_queues"] = @cpus.count
    end

    config
  end

  def vhost_backend_kek(key_wrapping_secrets)
    {
      "method" => "aes256-gcm",
      "key" => key_wrapping_secrets["key"].strip,
      "init_vector" => key_wrapping_secrets["init_vector"].strip,
      "auth_data" => Base64.strict_encode64(key_wrapping_secrets["auth_data"]).strip
    }
  end

  def wrap_key_b64(storage_key_encryption, key)
    key_bytes = [key].pack("H*")
    wrapped_key = storage_key_encryption.wrap_key(key_bytes).join
    Base64.strict_encode64(wrapped_key).strip
  end

  def write_vhost_service_file(vhost_backend, kek_arg)
    # systemd-analyze security result:
    # Overall exposure level for #{vhost_user_block_service}: 0.5 SAFE
    service_file_path = "/etc/systemd/system/#{vhost_user_block_service}"
    File.write(service_file_path, <<~SERVICE)
        [Unit]
        Description=Vhost Block Backend Service for #{@vm_name}
        After=network.target

        [Service]
        Slice=#{@slice}
        Environment=RUST_LOG=info
        Environment=RUST_BACKTRACE=1
        ExecStart=#{vhost_backend.bin_path} --config #{sp.vhost_backend_config} #{kek_arg}
        Restart=always
        User=#{@vm_name}
        Group=#{@vm_name}
        #{systemd_io_rate_limits}

        RemoveIPC=true
        NoNewPrivileges=true
        CapabilityBoundingSet=
        AmbientCapabilities=

        PrivateDevices=true
        DevicePolicy=closed
        DeviceAllow=/dev/null rw
        DeviceAllow=/dev/zero rw
        DeviceAllow=/dev/urandom rw
        DeviceAllow=/dev/random rw

        ProtectSystem=full
        ProtectHome=tmpfs
        ReadWritePaths=#{storage_root}
        PrivateTmp=true
        PrivateMounts=true

        ProtectKernelModules=true
        ProtectKernelTunables=true
        ProtectControlGroups=true
        ProtectClock=true
        ProtectHostname=true
        LockPersonality=true
        ProtectKernelLogs=true
        ProtectProc=invisible

        RestrictAddressFamilies=AF_UNIX
        RestrictNamespaces=true
        SystemCallArchitectures=native
        SystemCallFilter=@system-service

        MemoryDenyWriteExecute=yes
        RestrictSUIDSGID=yes
        RestrictRealtime=yes
        ProcSubset=pid
        PrivateNetwork=yes
        PrivateUsers=yes
        IPAddressDeny=any

        [Install]
        WantedBy=multi-user.target
    SERVICE
  end
end

# Handles vhost-backend >= 0.4.0 (TOML config v2 with structured secrets).
class VhostStorageVolumeV2 < VhostStorageVolume
  def vhost_backend_create_config(encryption_key, key_wrapping_secrets)
    config_path = sp.vhost_backend_config
    config_v2 = build_config_v2(encryption_key, key_wrapping_secrets)

    # Write stripe source config if present
    if (stripe_source = config_v2.stripe_source_toml)
      write_new_file(sp.vhost_backend_stripe_source_config, @vm_name) do |file|
        file.write(stripe_source)
        fsync_or_fail(file)
      end
    end

    # Write secrets config with restrictive permissions
    if (secrets = config_v2.secrets_toml)
      secrets_path = sp.vhost_backend_secrets_config
      rm_if_exists(secrets_path)
      File.open(secrets_path, "w", 0o600, flags: File::CREAT | File::EXCL) do |file|
        FileUtils.chown @vm_name, @vm_name, secrets_path
        file.write(secrets)
        fsync_or_fail(file)
      end
    end

    # Write main config (includes references to the other files)
    write_new_file(config_path, @vm_name) do |file|
      file.write(config_v2.main_toml)
      fsync_or_fail(file)
    end

    sync_parent_dir(config_path)
  end

  def vhost_backend_create_metadata(key_wrapping_secrets)
    vhost_backend = VhostBlockBackend.new(@vhost_backend_version)
    metadata_path = sp.vhost_backend_metadata
    config_path = sp.vhost_backend_config

    if @encrypted
      # v2: pass raw 32-byte KEK via stdin
      kek_stdin = Base64.decode64(key_wrapping_secrets["key"])
      kek_arg = "--kek /dev/stdin"
    else
      kek_stdin = ""
    end

    write_new_file(metadata_path, @vm_name) do |file|
      file.truncate(8 * 1024 * 1024)
    end

    r "#{vhost_backend.init_metadata_path.shellescape} -s #{@stripe_sector_count_shift}  --config #{config_path.shellescape} #{kek_arg}", stdin: kek_stdin
    sync_parent_dir(metadata_path)
  end

  def vhost_backend_create_service_file
    vhost_backend = VhostBlockBackend.new(@vhost_backend_version)
    # v2 config embeds the kek pipe path in the TOML, so no --kek CLI arg needed
    write_vhost_service_file(vhost_backend, nil)
  end

  def vhost_backend_start(key_wrapping_secrets)
    # Stop the service in case this is a retry.
    r "systemctl stop #{q_vhost_user_block_service}"

    unless @encrypted
      r "systemctl start #{q_vhost_user_block_service}"
      return
    end

    begin
      kek_pipe = sp.kek_pipe
      rm_if_exists(kek_pipe)
      File.mkfifo(kek_pipe, 0o600)
      FileUtils.chown @vm_name, @vm_name, kek_pipe

      r "systemctl start #{q_vhost_user_block_service}"

      Timeout.timeout(5) do
        # v2: write raw 32-byte KEK to the pipe
        kek_bytes = Base64.decode64(key_wrapping_secrets["key"])
        File.binwrite(kek_pipe, kek_bytes)
      end
    ensure
      FileUtils.rm_f(kek_pipe)
    end
  end

  private

  def build_config_v2(encryption_key, key_wrapping_secrets)
    VhostBackendConfigV2.new(
      disk_file: disk_file,
      vhost_sock: vhost_sock,
      rpc_socket_path: sp.rpc_socket_path,
      device_id: @device_id,
      num_queues: @cpus ? @cpus.count : @num_queues,
      queue_size: @queue_size,
      copy_on_read: @copy_on_read,
      write_through: write_through_device?,
      skip_sync: @skip_sync,
      image_path: @image_path,
      metadata_path: @image_path ? sp.vhost_backend_metadata : nil,
      cpus: @cpus,
      encrypted: @encrypted,
      encryption_key: encryption_key,
      kek: key_wrapping_secrets,
      kek_pipe: sp.kek_pipe,
      stripe_source_config_path: sp.vhost_backend_stripe_source_config,
      secrets_config_path: sp.vhost_backend_secrets_config
    )
  end
end
