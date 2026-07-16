# frozen_string_literal: true

require_relative "../lib/remote_storage_server"

RSpec.describe RemoteStorageServer do
  subject(:server) { described_class.new("vmxyz", "default", 0, "v0.5.0") }

  describe "#listen_config" do
    it "builds a listen config with the address and PSK" do
      lines = server.listen_config(4600, "cHNrYnl0ZXM=", "ubiblk-rss").split("\n")
      expect(lines).to include("[server]", "address = \"0.0.0.0:4600\"")
      expect(lines).to include("[server.psk]", "identity = \"ubiblk-rss\"", "secret.ref = \"psk\"")
      expect(lines).to include("[secrets.psk]", "source.inline = \"cHNrYnl0ZXM=\"", "encoding = \"base64\"")
    end
  end

  describe "#write_listen_config" do
    it "writes the config 0600 to the volume's storage dir" do
      expect(File).to receive(:write).with(%r{vmxyz/0/remote-stripe-listen\.conf}, /\[server\]/)
      expect(File).to receive(:chmod).with(0o600, %r{remote-stripe-listen\.conf})
      server.write_listen_config(4600, "p", "id")
    end
  end

  describe "#run" do
    it "refuses backends older than v0.5.0" do
      old = described_class.new("vmxyz", "default", 0, "v0.4.2")
      expect { old.run(4600, "p", "id", "kek") }.to raise_error(/v0.5.0 or later/)
    end

    it "writes the config, streams the KEK, and execs the server" do
      expect(server).to receive(:write_listen_config).with(4600, "p", "id")
      expect(server).to receive(:rm_if_exists)
      expect(File).to receive(:mkfifo)
      expect(FileUtils).to receive(:chown)
      expect(server).to receive(:fork).and_return(123)
      expect(Process).to receive(:detach).with(123)
      expect(server).to receive(:exec) do |env, path, *args|
        expect(env).to eq({"RUST_LOG" => "info"})
        expect(path).to eq("/opt/vhost-block-backend/v0.5.0/remote-stripe-server")
        expect(args).to include("-f", "--listen-config")
      end
      server.run(4600, "p", "id", "kek")
    end
  end
end
