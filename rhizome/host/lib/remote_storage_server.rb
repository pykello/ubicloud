# frozen_string_literal: true

require "fileutils"
require_relative "../../common/lib/util"
require_relative "storage_path"
require_relative "vhost_block_backend"
require_relative "kek_pipe"
require_relative "toml"

# Serves an existing (encrypted) storage volume over the ubiblk remote stripe
# protocol with TLS-PSK, using the v0.5.0 remote-stripe-server. It reuses the
# volume's own vhost-backend config (data/metadata/encryption and, if any, its
# stripe source), adding only a listen config for the address + PSK. The KEK is
# streamed to the volume's kek pipe, exactly as the vhost backend receives it.
class RemoteStorageServer
  include Toml
  include KekPipe

  def initialize(vm_name, storage_device, disk_index, vhost_block_backend_version)
    @vm_name = vm_name
    @sp = StoragePath.new(vm_name, storage_device, disk_index)
    @backend = VhostBlockBackend.new(vhost_block_backend_version)
  end

  def listen_config_path
    @listen_config_path ||= File.join(@sp.storage_dir, "remote-stripe-listen.conf")
  end

  def listen_config(port, psk, psk_identity)
    [
      toml_section("server", {"address" => "0.0.0.0:#{port}"}),
      toml_section("server.psk", {"identity" => psk_identity, "secret.ref" => "psk"}),
      toml_section("secrets.psk", {"source.inline" => psk, "encoding" => "base64"}),
      toml_section("danger_zone", {"enabled" => true, "allow_inline_plaintext_secrets" => true}),
    ].join("\n")
  end

  def write_listen_config(port, psk, psk_identity)
    File.write(listen_config_path, listen_config(port, psk, psk_identity))
    File.chmod(0o600, listen_config_path)
  end

  # Run the remote-stripe-server daemon in the foreground (this process becomes
  # the server). A forked writer streams the KEK to the volume's kek pipe, which
  # the server reads once at startup, then this process is replaced by the
  # server. Serving a volume whose VM is running is not supported (the vhost
  # backend already owns the kek pipe).
  def run(port, psk, psk_identity, kek_payload)
    fail "remote-stripe-server requires vhost block backend v0.5.0 or later" unless @backend.supports_remote_stripe_server?
    write_listen_config(port, psk, psk_identity)

    rm_if_exists(@sp.kek_pipe)
    File.mkfifo(@sp.kek_pipe, 0o600)
    FileUtils.chown @vm_name, @vm_name, @sp.kek_pipe
    writer = fork { write_kek_to_pipe(@sp.kek_pipe, kek_payload, timeout_sec: 60) }
    Process.detach(writer)

    exec(
      {"RUST_LOG" => "info"},
      @backend.remote_stripe_server_path,
      "-f", @sp.vhost_backend_config,
      "--listen-config", listen_config_path,
    )
  end
end
