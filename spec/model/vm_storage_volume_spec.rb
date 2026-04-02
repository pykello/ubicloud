# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe VmStorageVolume do
  it "can render a device_path" do
    vm = Vm.new(location: Location[Location::HETZNER_FSN1_ID]).tap { it.id = "eb3dbcb3-2c90-8b74-8fb4-d62a244d7ae5" }
    expect(described_class.new(disk_index: 7, vm:).device_path).to eq("/dev/disk/by-id/virtio-vmxcyvsc_7")
  end

  it "can render a device_path for aws" do
    prj = Project.create(name: "test-project")
    vm = Vm.new(location: Location.create(name: "us-west-2", provider: "aws", project_id: prj.id, display_name: "aws-us-west-2", ui_name: "AWS US East 1", visible: true)).tap { it.id = "eb3dbcb3-2c90-8b74-8fb4-d62a244d7ae5" }
    expect(described_class.new(disk_index: 2, vm:).device_path).to eq("/dev/nvme2n1")
  end

  it "returns correct spdk version if exists associated installation" do
    si = SpdkInstallation.new(version: "some-version")
    v = described_class.new(disk_index: 7)
    allow(v).to receive(:spdk_installation).and_return(si)
    expect(v.spdk_version).to eq("some-version")
  end

  it "returns nil spdk version if no associated installation" do
    v = described_class.new(disk_index: 7)
    allow(v).to receive(:spdk_installation).and_return(nil)
    expect(v.spdk_version).to be_nil
  end

  it "returns correct vhost_block_backend version if exists associated installation" do
    vbb = VhostBlockBackend.new(version_code: 10402)
    v = described_class.new(disk_index: 7)
    allow(v).to receive(:vhost_block_backend).and_return(vbb)
    expect(v.vhost_block_backend_version).to eq("v1.4.2")
  end

  it "returns nil vhost_block_backend version if no associated installation" do
    v = described_class.new(disk_index: 7)
    allow(v).to receive(:vhost_block_backend).and_return(nil)
    expect(v.vhost_block_backend_version).to be_nil
  end

  describe "#num_queues" do
    it "returns 1 for SPDK volumes" do
      v = described_class.new(disk_index: 7, vring_workers: 5)
      allow(v).to receive(:vhost_block_backend).and_return(nil)
      expect(v.num_queues).to eq(1)
    end

    it "returns vring_workers for vhost_block_backend volumes" do
      vm = Vm.new(vcpus: 4).tap { it.id = "eb3dbcb3-2c90-8b74-8fb4-d62a244d7ae5" }
      v = described_class.new(disk_index: 7, vm:, vring_workers: 5)
      allow(v).to receive(:vhost_block_backend).and_return(VhostBlockBackend.new)
      expect(v.num_queues).to eq(5)
    end
  end

  describe "#queue_size" do
    it "returns 256 for SPDK volumes" do
      v = described_class.new(disk_index: 7)
      allow(v).to receive(:vhost_block_backend).and_return(nil)
      expect(v.queue_size).to eq(256)
    end

    it "returns 64 for vhost_block_backend volumes" do
      v = described_class.new(disk_index: 7)
      allow(v).to receive(:vhost_block_backend).and_return(VhostBlockBackend.new)
      expect(v.queue_size).to eq(64)
    end
  end

  describe "#dump_metadata" do
    it "calls dump-storage-metadata on the host via ssh" do
      vm = instance_double(Vm, inhost_name: "test-vm")
      sshable = instance_double(Sshable)
      vm_host = instance_double(VmHost, sshable: sshable)
      allow(vm).to receive(:vm_host).and_return(vm_host)

      storage_volume_params = {"disk_index" => 2, "device_id" => "test-vm_2", "encrypted" => true}
      allow(vm).to receive(:storage_volumes).and_return([storage_volume_params])

      kek = instance_double(StorageKeyEncryptionKey)
      secret_hash = {"key" => "test-key"}
      allow(kek).to receive(:secret_key_material_hash).and_return(secret_hash)

      v = described_class.new(disk_index: 2)
      allow(v).to receive(:vm).and_return(vm)
      allow(v).to receive(:key_encryption_key_1).and_return(kek)

      expected_params = storage_volume_params.merge("key_wrapping_secrets" => secret_hash)
      expect(sshable).to receive(:cmd).with(
        "sudo host/bin/dump-storage-metadata :vm_name",
        vm_name: "test-vm",
        stdin: JSON.generate(expected_params)
      )

      v.dump_metadata
    end

    it "does not include key_wrapping_secrets for unencrypted volumes" do
      vm = instance_double(Vm, inhost_name: "test-vm")
      sshable = instance_double(Sshable)
      vm_host = instance_double(VmHost, sshable: sshable)
      allow(vm).to receive(:vm_host).and_return(vm_host)

      storage_volume_params = {"disk_index" => 2, "device_id" => "test-vm_2", "encrypted" => false}
      allow(vm).to receive(:storage_volumes).and_return([storage_volume_params])

      v = described_class.new(disk_index: 2)
      allow(v).to receive(:vm).and_return(vm)
      allow(v).to receive(:key_encryption_key_1).and_return(nil)

      expect(sshable).to receive(:cmd).with(
        "sudo host/bin/dump-storage-metadata :vm_name",
        vm_name: "test-vm",
        stdin: JSON.generate(storage_volume_params)
      )

      v.dump_metadata
    end
  end
end
