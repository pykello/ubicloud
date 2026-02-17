# frozen_string_literal: true

require_relative "../lib/vhost_backend_config_v2"
require "openssl"
require "base64"

RSpec.describe VhostBackendConfigV2 do
  let(:kek_raw) { OpenSSL::Cipher.new("aes-256-gcm").random_key }
  let(:kek_b64) { Base64.strict_encode64(kek_raw) }
  let(:key_wrapping_secrets) {
    {
      "algorithm" => "aes-256-gcm",
      "key" => kek_b64,
      "init_vector" => Base64.strict_encode64(OpenSSL::Cipher.new("aes-256-gcm").random_iv),
      "auth_data" => "Ubicloud-Test-Auth"
    }
  }

  let(:encryption_key) {
    dek = OpenSSL::Cipher.new("aes-256-xts").random_key.unpack1("H*")
    {key: dek[..63], key2: dek[64..]}
  }

  let(:base_params) {
    {
      disk_file: "/var/storage/test/2/disk.raw",
      vhost_sock: "/var/storage/test/2/vhost.sock",
      rpc_socket_path: "/var/storage/test/2/rpc.sock",
      device_id: "xyz01",
      num_queues: 4,
      queue_size: 128,
      kek_pipe: "/var/storage/test/2/kek.pipe",
      stripe_source_config_path: "/var/storage/test/2/vhost-backend-stripe-source.conf",
      secrets_config_path: "/var/storage/test/2/vhost-backend-secrets.conf"
    }
  }

  describe "#main_toml" do
    it "generates a minimal unencrypted config without includes" do
      config = described_class.new(base_params)
      toml = config.main_toml

      expect(toml).to include("[device]")
      expect(toml).to include('data_path = "/var/storage/test/2/disk.raw"')
      expect(toml).to include('vhost_socket = "/var/storage/test/2/vhost.sock"')
      expect(toml).to include('rpc_socket = "/var/storage/test/2/rpc.sock"')
      expect(toml).to include('device_id = "xyz01"')

      expect(toml).to include("[tuning]")
      expect(toml).to include("num_queues = 4")
      expect(toml).to include("queue_size = 128")
      expect(toml).to include("seg_size_max = 65536")
      expect(toml).to include("seg_count_max = 4")
      expect(toml).to include("poll_timeout_us = 1000")
      expect(toml).to include("write_through = false")

      expect(toml).not_to include("include")
      expect(toml).not_to include("[encryption]")
      expect(toml).not_to include("[secrets")
      expect(toml).not_to include("[stripe_source]")
    end

    it "includes stripe_source config file in include directive" do
      config = described_class.new(base_params.merge(
        image_path: "/var/storage/images/ubuntu.raw",
        metadata_path: "/var/storage/test/2/metadata"
      ))
      toml = config.main_toml

      expect(toml).to include('include = ["vhost-backend-stripe-source.conf"]')
      expect(toml).to include('metadata_path = "/var/storage/test/2/metadata"')
      expect(toml).not_to include("[stripe_source]")
    end

    it "includes both stripe_source and secrets config files when encrypted with image" do
      config = described_class.new(base_params.merge(
        image_path: "/var/storage/images/ubuntu.raw",
        metadata_path: "/var/storage/test/2/metadata",
        encrypted: true,
        encryption_key: encryption_key,
        kek: key_wrapping_secrets
      ))
      toml = config.main_toml

      expect(toml).to include('include = ["vhost-backend-stripe-source.conf", "vhost-backend-secrets.conf"]')
      expect(toml).to include("[encryption]")
      expect(toml).to include('xts_key = { ref = "xts-key" }')
    end

    it "includes only secrets config file when encrypted without image" do
      config = described_class.new(base_params.merge(
        encrypted: true,
        encryption_key: encryption_key,
        kek: key_wrapping_secrets
      ))
      toml = config.main_toml

      expect(toml).to include('include = ["vhost-backend-secrets.conf"]')
      expect(toml).to include("[encryption]")
    end

    it "includes cpus in tuning when set" do
      config = described_class.new(base_params.merge(cpus: [0, 2, 4]))
      toml = config.main_toml

      expect(toml).to include("cpus = [0, 2, 4]")
    end

    it "includes write_through when set" do
      config = described_class.new(base_params.merge(write_through: true))
      toml = config.main_toml

      expect(toml).to include("write_through = true")
    end
  end

  describe "#stripe_source_toml" do
    it "returns nil when no image_path" do
      config = described_class.new(base_params)
      expect(config.stripe_source_toml).to be_nil
    end

    it "generates stripe source section" do
      config = described_class.new(base_params.merge(
        image_path: "/var/storage/images/ubuntu.raw",
        metadata_path: "/var/storage/test/2/metadata",
        copy_on_read: true
      ))
      toml = config.stripe_source_toml

      expect(toml).to include("[stripe_source]")
      expect(toml).to include('type = "raw"')
      expect(toml).to include('image_path = "/var/storage/images/ubuntu.raw"')
      expect(toml).to include("copy_on_read = true")
    end
  end

  describe "#secrets_toml" do
    it "returns nil when not encrypted" do
      config = described_class.new(base_params)
      expect(config.secrets_toml).to be_nil
    end

    it "generates secrets section with wrapped XTS key and KEK pipe" do
      config = described_class.new(base_params.merge(
        encrypted: true,
        encryption_key: encryption_key,
        kek: key_wrapping_secrets
      ))
      toml = config.secrets_toml

      expect(toml).to include("[secrets.xts-key]")
      expect(toml).to include('encoding = "base64"')
      expect(toml).to include('kek = { ref = "kek" }')
      expect(toml).to include("[secrets.kek]")
      expect(toml).to include('source = { file = "/var/storage/test/2/kek.pipe" }')
    end
  end

  describe "StorageKeyEncryption.aes256gcm_encrypt" do
    it "produces correct format: 12-byte nonce + ciphertext + 16-byte tag" do
      plaintext = SecureRandom.random_bytes(64)
      encrypted = StorageKeyEncryption.aes256gcm_encrypt(kek_raw, "test-secret", plaintext)

      # 12 nonce + 64 ciphertext + 16 tag = 92 bytes
      expect(encrypted.bytesize).to eq(92)
    end

    it "can be decrypted with matching KEK and AAD" do
      plaintext = SecureRandom.random_bytes(64)
      encrypted = StorageKeyEncryption.aes256gcm_encrypt(kek_raw, "xts-key", plaintext)

      # Decrypt to verify
      nonce = encrypted[0, 12]
      ciphertext = encrypted[12, 64]
      tag = encrypted[76, 16]

      decipher = OpenSSL::Cipher.new("aes-256-gcm")
      decipher.decrypt
      decipher.key = kek_raw
      decipher.iv = nonce
      decipher.auth_data = "xts-key"
      decipher.auth_tag = tag
      decrypted = decipher.update(ciphertext) + decipher.final

      expect(decrypted).to eq(plaintext)
    end

    it "fails to decrypt with wrong AAD" do
      plaintext = SecureRandom.random_bytes(64)
      encrypted = StorageKeyEncryption.aes256gcm_encrypt(kek_raw, "xts-key", plaintext)

      nonce = encrypted[0, 12]
      ciphertext = encrypted[12, 64]
      tag = encrypted[76, 16]

      decipher = OpenSSL::Cipher.new("aes-256-gcm")
      decipher.decrypt
      decipher.key = kek_raw
      decipher.iv = nonce
      decipher.auth_data = "wrong-aad"
      decipher.auth_tag = tag

      expect {
        decipher.update(ciphertext) + decipher.final
      }.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end

  describe "#kek_bytes" do
    it "returns the raw 32-byte KEK" do
      config = described_class.new(base_params.merge(
        encrypted: true,
        encryption_key: encryption_key,
        kek: key_wrapping_secrets
      ))

      expect(config.kek_bytes).to eq(kek_raw)
      expect(config.kek_bytes.bytesize).to eq(32)
    end
  end

  describe "encrypted config round-trip" do
    it "wraps XTS key in secrets_toml so it can be decrypted with the KEK" do
      config = described_class.new(base_params.merge(
        encrypted: true,
        encryption_key: encryption_key,
        kek: key_wrapping_secrets
      ))
      toml = config.secrets_toml

      # Extract the wrapped key from the TOML
      match = toml.match(/source = \{ inline = "([^"]+)" \}/)
      expect(match).not_to be_nil
      wrapped_b64 = match[1]
      wrapped = Base64.strict_decode64(wrapped_b64)

      # Should be 92 bytes: 12 nonce + 64 ciphertext + 16 tag
      expect(wrapped.bytesize).to eq(92)

      # Decrypt with KEK
      nonce = wrapped[0, 12]
      ciphertext = wrapped[12, 64]
      tag = wrapped[76, 16]

      decipher = OpenSSL::Cipher.new("aes-256-gcm")
      decipher.decrypt
      decipher.key = kek_raw
      decipher.iv = nonce
      decipher.auth_data = "xts-key"
      decipher.auth_tag = tag
      decrypted = decipher.update(ciphertext) + decipher.final

      # Should match the original XTS key (key1 + key2 concatenated)
      key1_bytes = [encryption_key[:key]].pack("H*")
      key2_bytes = [encryption_key[:key2]].pack("H*")
      expect(decrypted).to eq(key1_bytes + key2_bytes)
    end
  end
end
