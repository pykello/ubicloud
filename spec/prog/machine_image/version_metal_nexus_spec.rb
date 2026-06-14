# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::VersionMetalNexus do
  subject(:prog) { described_class.new(strand) }

  let(:project) { Project.create(name: "test-mi-project") }
  let(:vm_host) { create_vm_host }
  let(:vhost_block_backend) { create_vhost_block_backend(version: "v0.4.1", allocation_weight: 50, vm_host_id: vm_host.id) }
  let(:source_vm) {
    vm = create_vm(vm_host_id: vm_host.id, project_id: project.id)
    Strand.create_with_id(vm, prog: "Vm::Nexus", label: "stopped")
    sd = StorageDevice.create(name: "vda", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
    VmStorageVolume.create(
      vm_id: vm.id, boot: true, size_gib: 5, disk_index: 0,
      storage_device_id: sd.id, vhost_block_backend_id: vhost_block_backend.id,
      key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "src").id,
      vring_workers: 1, track_written: true,
    )
    vm
  }
  let(:machine_image) { MachineImage.create(name: "test-image", arch: "x64", project_id: project.id, location_id: Location::HETZNER_FSN1_ID) }
  let(:store) {
    MachineImageStore.create(project_id: project.id, location_id: Location::HETZNER_FSN1_ID,
      provider: "r2", region: "auto", endpoint: "https://r2.example.com/",
      bucket: "test-bucket", access_key: "ak", secret_key: "sk")
  }
  let(:mi_version) { MachineImageVersion.create(machine_image_id: machine_image.id, version: "1.0", actual_size_mib: 5 * 1024) }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "k") }
  let(:mi_version_metal) {
    MachineImageVersionMetal.create_with_id(mi_version,
      status: "ready", archive_size_mib: 1, archive_kek_id: archive_kek.id,
      store_id: store.id, store_prefix: "#{project.ubid}/#{machine_image.ubid}/1.0")
  }
  let(:strand) {
    Strand.create_with_id(mi_version_metal,
      prog: "MachineImage::VersionMetalNexus",
      label: "wait", stack: [{}])
  }

  describe ".assemble_from_vm" do
    it "validates the source VM and creates a strand at archive_from_vm" do
      vhost_block_backend
      s = described_class.assemble_from_vm(machine_image, "1.0", source_vm, store, destroy_source_after: true)
      expect(s).to have_attributes(prog: "MachineImage::VersionMetalNexus", label: "archive_from_vm")
      expect(MachineImageVersionMetal[s.id].status).to eq("creating")
      expect(s.stack.first.values_at("source_vm_id", "destroy_source_after", "set_as_latest"))
        .to eq([source_vm.id, true, true])
    end

    it "raises when the source VM fails preflight" do
      machine_image.update(arch: "arm64")
      expect {
        described_class.assemble_from_vm(machine_image, "1.0", source_vm, store)
      }.to raise_error(MachineImageError, /does not match machine image arch/)
    end
  end

  describe ".assemble_from_url" do
    it "creates a strand at archive_from_url and records the picked vbb host" do
      vhost_block_backend
      s = described_class.assemble_from_url(machine_image, "2.0", "https://x/img", "abc", store)
      expect(s.label).to eq("archive_from_url")
      expect(s.stack.first.values_at("url", "sha256sum", "vm_host_id", "vhost_block_backend_version"))
        .to eq(["https://x/img", "abc", vm_host.id, "v0.4.1"])
    end

    it "raises when no vm host supports archive in the location" do
      expect {
        described_class.assemble_from_url(machine_image, "2.0", "https://x/img", "abc", store)
      }.to raise_error("no vm host with archive support found in location")
    end
  end

  describe "#archive_from_vm" do
    it "buds CreateVersionMetal at the archive label and hops to wait_archive" do
      strand_vm = Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "archive_from_vm",
        stack: [{"source_vm_id" => source_vm.id, "destroy_source_after" => false, "set_as_latest" => true}])
      expect { described_class.new(strand_vm).archive_from_vm }.to hop("wait_archive")
      child = strand_vm.children_dataset.first
      expect(child).to have_attributes(prog: "MachineImage::CreateVersionMetal", label: "archive")
    end
  end

  describe "#archive_from_url" do
    it "buds CreateVersionMetalFromUrl at the archive label and hops to wait_archive" do
      strand_url = Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "archive_from_url",
        stack: [{"url" => "https://x/img", "sha256sum" => "abc",
                 "vm_host_id" => vm_host.id, "vhost_block_backend_version" => "v0.4.1",
                 "set_as_latest" => true}])
      expect { described_class.new(strand_url).archive_from_url }.to hop("wait_archive")
      child = strand_url.children_dataset.first
      expect(child).to have_attributes(prog: "MachineImage::CreateVersionMetalFromUrl", label: "archive")
    end
  end

  describe "#wait_archive" do
    it "hops to wait when no children are running" do
      expect { prog.wait_archive }.to hop("wait")
    end
  end

  describe "#wait" do
    it "naps when destroy is not requested" do
      expect { prog.wait }.to nap(6 * 60 * 60)
    end

    it "hops to destroy when destroy semaphore is set" do
      strand
      mi_version_metal.incr_destroy
      expect { described_class.new(strand).wait }.to hop("destroy")
    end
  end

  describe "#destroy" do
    it "buds DestroyVersionMetal at prep_destroy and hops to wait_destroy" do
      expect { prog.destroy }.to hop("wait_destroy")
      child = strand.children_dataset.first
      expect(child).to have_attributes(prog: "MachineImage::DestroyVersionMetal", label: "prep_destroy")
    end
  end

  describe "#wait_destroy" do
    it "hops to popped when no children are running" do
      expect { prog.wait_destroy }.to hop("popped")
    end
  end

  describe "#popped" do
    it "pops" do
      expect { prog.popped }.to exit({"msg" => "Metal machine image version is destroyed"})
    end
  end
end
