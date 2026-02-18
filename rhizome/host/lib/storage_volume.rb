# frozen_string_literal: true

require_relative "../../common/lib/util"

require "fileutils"
require "json"
require "openssl"
require "base64"
require "timeout"
require "yaml"
require_relative "boot_image"
require_relative "vm_path"
require_relative "storage_key_encryption"
require_relative "storage_path"

class StorageVolume
  def self.new(vm_name, params)
    return super if self != StorageVolume

    version = params["vhost_block_backend_version"]
    if version.nil?
      SpdkStorageVolume.new(vm_name, params)
    elsif Gem::Version.new(version.delete_prefix("v")) >= Gem::Version.new("0.4.0")
      VhostStorageVolumeV2.new(vm_name, params)
    else
      VhostStorageVolume.new(vm_name, params)
    end
  end

  attr_reader :image_path, :read_only, :num_queues, :queue_size

  def initialize(vm_name, params)
    @vm_name = vm_name
    @disk_index = params["disk_index"]
    @device_id = params["device_id"]
    @encrypted = params["encrypted"]
    @disk_size_gib = params["size_gib"]
    @skip_sync = params["skip_sync"] || false
    @image_path = BootImage.new(params["image"], params["image_version"]).image_path if params["image"]
    @device = params["storage_device"] || DEFAULT_STORAGE_DEVICE
    @read_only = params["read_only"] || false
    @max_read_mbytes_per_sec = params["max_read_mbytes_per_sec"]
    @max_write_mbytes_per_sec = params["max_write_mbytes_per_sec"]
    @num_queues = params.fetch("num_queues", 1)
    @queue_size = params.fetch("queue_size", 256)
    @copy_on_read = params.fetch("copy_on_read", false)
    @cpus = params["cpus"]
  end

  def vp
    @vp ||= VmPath.new(@vm_name)
  end

  def spdk_service
    nil
  end

  def vhost_user_block_service
    nil
  end

  def write_new_file(path, user)
    rm_if_exists(path)

    File.open(path, "w", 0o600, flags: File::CREAT | File::EXCL) do |file|
      FileUtils.chown user, user, path
      yield file
    end
  end

  def setup_data_encryption_key(key_wrapping_secrets)
    data_encryption_key = OpenSSL::Cipher.new("aes-256-xts").random_key.unpack1("H*")

    result = {
      cipher: "AES_XTS",
      key: data_encryption_key[..63],
      key2: data_encryption_key[64..]
    }

    key_file = data_encryption_key_path

    # save encrypted key
    sek = StorageKeyEncryption.new(key_wrapping_secrets)
    sek.write_encrypted_dek(key_file, result)

    FileUtils.chown @vm_name, @vm_name, key_file
    FileUtils.chmod "u=rw,g=,o=", key_file

    sync_parent_dir(key_file)

    result
  end

  def read_data_encryption_key(key_wrapping_secrets)
    sek = StorageKeyEncryption.new(key_wrapping_secrets)
    sek.read_encrypted_dek(data_encryption_key_path)
  end

  def create_empty_disk_file(disk_size_mib: @disk_size_gib * 1024)
    FileUtils.touch(disk_file)
    File.truncate(disk_file, disk_size_mib * 1024 * 1024)

    set_disk_file_permissions
  end

  def set_disk_file_permissions
    FileUtils.chown @vm_name, @vm_name, disk_file

    # don't allow others to read user's disk
    FileUtils.chmod "u=rw,g=r,o=", disk_file

    # allow spdk to access the image
    r "setfacl -m u:spdk:rw #{disk_file.shellescape}"
  end

  def write_through_device?
    st = File.stat(disk_file)

    rp = File.realpath("/sys/dev/block/#{st.dev_major}:#{st.dev_minor}")
    dev = File.basename(rp)
    base = File.exist?("/sys/block/#{dev}") ? dev : File.basename(File.dirname(rp))

    File.read("/sys/block/#{base}/queue/write_cache").include?("write through")
  end

  def stop_service_if_loaded(name)
    r "systemctl stop #{name.shellescape}"
  rescue CommandFail => e
    raise unless e.stderr.include?("not loaded")
  end

  def systemd_io_rate_limits
    limits = {IOReadBandwidthMax: @max_read_mbytes_per_sec,
              IOWriteBandwidthMax: @max_write_mbytes_per_sec}.compact
    return "" if limits.empty?

    dev = persistent_device_id(storage_dir)
    limits
      .map { |(key, mb)| "#{key}=#{dev} #{mb * 1024 * 1024}" }
      .join("\n")
  end

  def persistent_device_id(path)
    path_stat = File.stat(path)

    Dir["/dev/disk/by-id/*"].each do |id|
      dev_path = File.realpath(id)
      dev_stat = File.stat(dev_path)
      next unless dev_stat.rdev_major == path_stat.dev_major && dev_stat.rdev_minor == path_stat.dev_minor

      # Choose stable symlink types by subsystem:
      #  - SSDs: Use identifiers starting with 'wwn' (World Wide Name), globally unique.
      #  - NVMe: Use identifiers starting with 'nvme-eui', also globally unique.
      #  - MD devices: Use uuid identifiers.
      dev = File.basename(dev_path)
      return id if (dev.start_with?("nvme") && id.include?("nvme-eui.")) ||
        (dev.start_with?("sd") && id.include?("wwn-")) ||
        (dev.start_with?("md") && id.include?("md-uuid-"))
    rescue SystemCallError
      next
    end

    raise "No persistent device ID found for storage path: #{path}"
  end

  def sp
    @sp ||= StoragePath.new(@vm_name, @device, @disk_index)
  end

  def storage_root
    @storage_root ||= sp.storage_root
  end

  def storage_dir
    @storage_dir ||= sp.storage_dir
  end

  def disk_file
    @disk_file ||= sp.disk_file
  end

  def data_encryption_key_path
    @dek_path ||= sp.data_encryption_key
  end

  def vhost_sock
    @vhost_sock ||= sp.vhost_sock
  end
end

require_relative "spdk_storage_volume"
require_relative "vhost_storage_volume"
