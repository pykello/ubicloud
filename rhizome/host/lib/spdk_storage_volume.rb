# frozen_string_literal: true

require_relative "spdk_path"
require_relative "spdk_rpc"
require_relative "spdk_setup"

class SpdkStorageVolume < StorageVolume
  def initialize(vm_name, params)
    super
    @use_bdev_ubi = params["use_bdev_ubi"] || false
    @spdk_version = params["spdk_version"]
  end

  def prep(key_wrapping_secrets)
    # Device path is intended to be created by system admin, so fail loudly if
    # it doesn't exist
    fail "Storage device directory doesn't exist: #{sp.device_path}" if !File.exist?(sp.device_path)

    FileUtils.mkdir_p storage_dir
    FileUtils.chown @vm_name, @vm_name, storage_dir
    encryption_key = setup_data_encryption_key(key_wrapping_secrets) if @encrypted

    if @image_path.nil?
      fail "bdev_ubi requires a base image" if @use_bdev_ubi

      create_empty_disk_file
      return
    end

    verify_imaged_disk_size

    if @use_bdev_ubi
      create_ubi_writespace(encryption_key)
    elsif @encrypted
      create_empty_disk_file
      encrypted_image_copy(encryption_key, @image_path)
    else
      unencrypted_image_copy
    end
  end

  def start(key_wrapping_secrets)
    encryption_key = read_data_encryption_key(key_wrapping_secrets) if @encrypted
    retries = 0
    begin
      setup_spdk_bdev(encryption_key)
      set_qos_limits
      setup_spdk_vhost
    rescue SpdkExists
      # If some of SPDK artifacts exist, purge and retry. But retry only once
      # to prevent potential retry loops.
      if retries == 0
        retries += 1
        purge_spdk_artifacts
        retry
      end
      raise
    end
  end

  def purge_spdk_artifacts
    vhost_controller = SpdkPath.vhost_controller(@vm_name, @disk_index)

    rpc_client.vhost_delete_controller(vhost_controller)

    non_ubi_bdev = @use_bdev_ubi ? "#{@device_id}_base" : @device_id

    if @use_bdev_ubi
      rpc_client.bdev_ubi_delete(@device_id)
    end

    if @encrypted
      rpc_client.bdev_crypto_delete(non_ubi_bdev)
      rpc_client.bdev_aio_delete("#{@device_id}_aio")
      rpc_client.accel_crypto_key_destroy("#{@device_id}_key")
    else
      rpc_client.bdev_aio_delete(non_ubi_bdev)
    end

    rm_if_exists(SpdkPath.vhost_sock(vhost_controller))
  end

  def spdk_service
    @spdk_service ||= SpdkSetup.new(@spdk_version).spdk_service if @spdk_version
  end

  def rpc_client
    @rpc_client ||= SpdkRpc.new(SpdkPath.rpc_sock(@spdk_version))
  end

  def setup_spdk_bdev(encryption_key)
    non_ubi_bdev = @use_bdev_ubi ? "#{@device_id}_base" : @device_id

    if encryption_key
      key_name = "#{@device_id}_key"
      aio_bdev = "#{@device_id}_aio"
      rpc_client.accel_crypto_key_create(
        key_name,
        encryption_key[:cipher],
        encryption_key[:key],
        encryption_key[:key2]
      )
      rpc_client.bdev_aio_create(aio_bdev, disk_file, 512)
      rpc_client.bdev_crypto_create(non_ubi_bdev, aio_bdev, key_name)
    else
      rpc_client.bdev_aio_create(non_ubi_bdev, disk_file, 512)
    end

    if @use_bdev_ubi
      rpc_client.bdev_ubi_create(@device_id, non_ubi_bdev, @image_path, @skip_sync)
    end
  end

  def set_qos_limits
    return unless @max_read_mbytes_per_sec || @max_write_mbytes_per_sec

    rpc_client.bdev_set_qos_limit(
      @device_id,
      r_mbytes_per_sec: @max_read_mbytes_per_sec,
      w_mbytes_per_sec: @max_write_mbytes_per_sec
    )
  end

  def setup_spdk_vhost
    vhost_controller = SpdkPath.vhost_controller(@vm_name, @disk_index)
    spdk_vhost_sock = SpdkPath.vhost_sock(vhost_controller)

    rpc_client.vhost_create_blk_controller(vhost_controller, @device_id)

    # don't allow others to access the vhost socket
    FileUtils.chmod "u=rw,g=r,o=", spdk_vhost_sock

    # allow vm user to access the vhost socket
    r "setfacl -m u:#{@vm_name}:rw #{spdk_vhost_sock.shellescape}"

    # create a symlink to the socket in the per vm storage dir
    rm_if_exists(vhost_sock)
    FileUtils.ln_s spdk_vhost_sock, vhost_sock

    # Change ownership of the symlink. FileUtils.chown uses File.lchown for
    # symlinks and doesn't follow links. We don't use File.lchown directly
    # because it expects numeric uid & gid, which is less convenient.
    FileUtils.chown @vm_name, @vm_name, vhost_sock

    vhost_sock
  end

  def unencrypted_image_copy
    q_image_path = @image_path.shellescape
    q_disk_file = disk_file.shellescape

    r "cp --reflink=auto #{q_image_path} #{q_disk_file}"
    r "truncate -s #{@disk_size_gib}G #{q_disk_file}"

    set_disk_file_permissions
  end

  def verify_imaged_disk_size
    size = File.size(@image_path)
    fail "Image size greater than requested disk size" unless size <= @disk_size_gib * 2**30
  end

  def encrypted_image_copy(encryption_key, input_file, block_size: 2097152, count: nil)
    # Note that spdk_dd doesn't interact with the main spdk process. It is a
    # tool which starts the spdk infra as a separate process, creates bdevs
    # from config, does the copy, and exits. Since it is a separate process
    # for each image, although bdev names are same, they don't conflict.
    # Goal is to copy the image into disk_file, which will be registered
    # in the main spdk daemon after this function returns.

    bdev_conf = [{
      method: "bdev_aio_create",
      params: {
        name: "aio0",
        block_size: 512,
        filename: disk_file,
        readonly: false
      }
    },
      {
        method: "bdev_crypto_create",
        params: {
          base_bdev_name: "aio0",
          name: "crypt0",
          key_name: "super_key"
        }
      }]

    accel_conf = [
      {
        method: "accel_crypto_key_create",
        params: {
          name: "super_key",
          cipher: encryption_key[:cipher],
          key: encryption_key[:key],
          key2: encryption_key[:key2]
        }
      }
    ]

    spdk_config_json = {
      subsystems: [
        {
          subsystem: "accel",
          config: accel_conf
        },
        {
          subsystem: "bdev",
          config: bdev_conf
        }
      ]
    }.to_json

    # spdk_dd uses the same spdk app infra, so it will bind to an rpc socket,
    # which we won't use. But its path shouldn't conflict with other VM setups,
    # so it doesn't error out in concurrent VM creations.
    rpc_socket = "/var/tmp/spdk_dd.sock.#{@vm_name}"

    count_param = count.nil? ? "" : "--count #{count}"

    r("#{SpdkPath.bin(@spdk_version, "spdk_dd")} --config /dev/stdin " \
    "--disable-cpumask-locks " \
    "--rpc-socket #{rpc_socket.shellescape} " \
    "--if #{input_file.shellescape} " \
    "--ob crypt0 " \
    "--bs=#{block_size} #{count_param}", stdin: spdk_config_json)
  end

  def create_ubi_writespace(encryption_key)
    create_empty_disk_file(disk_size_mib: @disk_size_gib * 1024 + 16)
    if @encrypted
      # just clear the metadata section, i.e. first 8MB
      encrypted_image_copy(encryption_key, "/dev/zero", block_size: 2097152, count: 4)
    end
  end
end
