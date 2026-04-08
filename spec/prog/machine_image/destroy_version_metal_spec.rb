# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::DestroyVersionMetal do
  subject(:prog) {
    described_class.new(described_class.assemble(mi_version_metal, destroy_version: true))
  }

  let(:mi_version_metal) { create_machine_image_version_metal }
  let(:mi_version) { mi_version_metal.machine_image_version }
  let(:machine_image) { mi_version.machine_image }
  let(:project) { machine_image.project }
  let(:archive_kek) { mi_version_metal.archive_kek }
  let(:store) { mi_version_metal.store }

  describe ".assemble" do
    it "disables the version metal and creates a strand" do
      strand = described_class.assemble(mi_version_metal)

      expect(mi_version_metal.reload.enabled).to be false
      expect(strand.prog).to eq("MachineImage::DestroyVersionMetal")
      expect(strand.label).to eq("destroy_objects")
      expect(strand.stack.first["subject_id"]).to eq(mi_version_metal.id)
      expect(strand.stack.first["destroy_version"]).to be true
    end

    it "passes destroy_version: false through to the stack" do
      strand = described_class.assemble(mi_version_metal, destroy_version: false)

      expect(strand.stack.first["destroy_version"]).to be false
    end

    it "fails when destroying the latest version of a machine image" do
      machine_image.update(latest_version_id: mi_version.id)

      expect {
        described_class.assemble(mi_version_metal)
      }.to raise_error("Cannot destroy the latest version of a machine image")
    end

    it "fails when VMs are still using this version" do
      vm_host = create_vm_host
      vhost_block_backend = create_vhost_block_backend(allocation_weight: 50, vm_host_id: vm_host.id)
      vm = create_vm(vm_host_id: vm_host.id, project_id: project.id)
      sd = StorageDevice.create(name: "vda", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
      VmStorageVolume.create(
        vm_id: vm.id, boot: true, size_gib: 5, disk_index: 0,
        storage_device_id: sd.id, vhost_block_backend_id: vhost_block_backend.id,
        key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "k1").id,
        machine_image_version_id: mi_version.id,
        vring_workers: 1,
      )

      expect {
        described_class.assemble(mi_version_metal)
      }.to raise_error("VMs are still using this machine image version")
    end
  end

  describe "#destroy_objects" do
    let(:s3_client) { Aws::S3::Client.new(stub_responses: true) }

    before do
      allow(Aws::S3::Client).to receive(:new).with(
        access_key_id: store.access_key,
        secret_access_key: store.secret_key,
        endpoint: store.endpoint,
        region: store.region,
        force_path_style: true,
      ).and_return(s3_client)
    end

    it "hops to update_database when no objects are returned" do
      s3_client.stub_responses(:list_objects_v2, {contents: [], is_truncated: false})

      expect { prog.destroy_objects }.to hop("update_database")
    end

    it "deletes the first page of objects and naps" do
      s3_client.stub_responses(
        :list_objects_v2,
        {contents: [{key: "obj1"}, {key: "obj2"}], is_truncated: true},
        {contents: [{key: "obj3"}], is_truncated: false},
      )
      expect(s3_client).to receive(:delete_objects).with(
        bucket: store.bucket,
        delete: {objects: [{key: "obj1"}, {key: "obj2"}]},
      ).and_call_original
      expect(Clog).to receive(:emit).with(
        "Deleting machine image archive objects",
        {
          machine_image: mi_version.machine_image.ubid,
          version: mi_version.version,
          count: 2,
          truncated: true,
        },
      )

      expect { prog.destroy_objects }.to nap(0)
    end
  end

  describe "#update_database" do
    it "destroys the version metal, archive kek, and version when destroy_version is true" do
      mi_version_metal_id = mi_version_metal.id
      kek_id = archive_kek.id
      mi_version_id = mi_version.id

      expect { prog.update_database }.to exit({"msg" => "Metal machine image version is destroyed"})

      expect(MachineImageVersionMetal[mi_version_metal_id]).to be_nil
      expect(StorageKeyEncryptionKey[kek_id]).to be_nil
      expect(MachineImageVersion[mi_version_id]).to be_nil
    end

    it "preserves the underlying version when destroy_version is false" do
      refresh_frame(prog, new_values: {"destroy_version" => false})

      mi_version_metal_id = mi_version_metal.id
      kek_id = archive_kek.id
      mi_version_id = mi_version.id

      expect { prog.update_database }.to exit({"msg" => "Metal machine image version is destroyed"})

      expect(MachineImageVersionMetal[mi_version_metal_id]).to be_nil
      expect(StorageKeyEncryptionKey[kek_id]).to be_nil
      expect(MachineImageVersion[mi_version_id]).not_to be_nil
    end
  end
end
