# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::DestroyVersionMetal do
  subject(:prog) {
    described_class.new(Strand.create_with_id(mi_version_metal,
      prog: "MachineImage::DestroyVersionMetal", label: "destroy_objects"))
  }

  let(:project) { Project.create(name: "p") }
  let(:store) {
    MachineImageStore.create(project_id: project.id, location_id: Location::HETZNER_FSN1_ID,
      provider: "r2", region: "auto", endpoint: "https://r2.example.com/",
      bucket: "b", access_key: "ak", secret_key: "sk")
  }
  let(:machine_image) { MachineImage.create(name: "mi", project_id: project.id, arch: "x64", location_id: Location::HETZNER_FSN1_ID) }
  let(:mi_version) { MachineImageVersion.create(machine_image_id: machine_image.id, version: "v1", actual_size_mib: 5 * 1024) }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "k") }
  let(:mi_version_metal) {
    MachineImageVersionMetal.create_with_id(mi_version,
      status: "destroying", archive_size_mib: 1024,
      archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")
  }

  describe "#prep_destroy" do
    let(:strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::DestroyVersionMetal", label: "prep_destroy")
    }
    let(:prep_prog) { described_class.new(strand) }

    before { mi_version_metal.update(status: "ready") }

    it "flips status to destroying, finalizes billing, reassigns latest, hops to wait_vms" do
      machine_image.update(latest_version_id: mi_version.id)
      br = mi_version_metal.create_billing_record
      br.update(span: Sequel.pg_range((Time.now - 60)..))

      expect { prep_prog.prep_destroy }.to hop("wait_vms")
        .and change { mi_version_metal.reload.status }.from("ready").to("destroying")
        .and change { br.reload.span.end }.from(nil).to(be_within(60).of(Time.now))
      expect(machine_image.reload.latest_version_id).to be_nil
    end

    it "is idempotent when already destroying" do
      mi_version_metal.update(status: "destroying")
      expect { prep_prog.prep_destroy }.to hop("wait_vms")
    end
  end

  describe "#wait_vms" do
    let(:vm_host) { create_vm_host }
    let(:vhost) { create_vhost_block_backend(allocation_weight: 50, vm_host_id: vm_host.id) }
    let(:project_for_vm) { Project.create(name: "vmp") }
    let(:strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::DestroyVersionMetal", label: "wait_vms")
    }
    let(:wait_prog) { described_class.new(strand) }

    it "naps while a VM still references the MIV" do
      vm = create_vm(vm_host_id: vm_host.id, project_id: project_for_vm.id)
      sd = StorageDevice.create(name: "sda", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
      VmStorageVolume.create(
        vm_id: vm.id, boot: true, size_gib: 1, disk_index: 0,
        storage_device_id: sd.id, vhost_block_backend_id: vhost.id,
        key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "k").id,
        machine_image_version_id: mi_version.id,
        vring_workers: 1,
      )
      expect { wait_prog.wait_vms }.to nap(30)
    end

    it "hops to destroy_objects once no VM references the MIV" do
      expect { wait_prog.wait_vms }.to hop("destroy_objects")
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
        http_open_timeout: 5,
        http_read_timeout: 20,
        retry_limit: 0,
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

      expect { prog.destroy_objects }.to nap(0)
    end

    it "logs and naps if delete_objects returns per-object errors" do
      s3_client.stub_responses(
        :list_objects_v2,
        {contents: [{key: "obj1"}, {key: "obj2"}], is_truncated: false},
      )
      expect(s3_client).to receive(:delete_objects).and_return(
        Aws::S3::Types::DeleteObjectsOutput.new(
          deleted: [Aws::S3::Types::DeletedObject.new(key: "obj1")],
          errors: [Aws::S3::Types::Error.new(key: "obj2", code: "AccessDenied", message: "Access Denied")],
        ),
      )

      expect(Clog).to receive(:emit).with("Failed to delete some machine image archive objects", {
        machine_image: mi_version.machine_image.ubid,
        version: mi_version.version,
        count: 1,
        first_error: {code: "AccessDenied", key: "obj2", message: "Access Denied"},
      })

      expect { prog.destroy_objects }.to nap(30)
    end
  end

  describe "#update_database" do
    it "destroys the version metal, archive kek, and version when status is 'destroying'" do
      expect { prog.update_database }.to exit({"msg" => "Metal machine image version is destroyed"})
        .and change { mi_version_metal.exists? }.from(true).to(false)
        .and change { archive_kek.exists? }.from(true).to(false)
        .and change { mi_version.exists? }.from(true).to(false)
    end

    it "preserves the DB rows when status is 'failed'" do
      mi_version_metal.update(status: "failed", archive_size_mib: nil)
      expect { prog.update_database }.to exit({"msg" => "Metal machine image version archive objects deleted"})
      expect(mi_version_metal.exists?).to be true
      expect(archive_kek.exists?).to be true
      expect(mi_version.exists?).to be true
      expect(mi_version_metal.reload.status).to eq("failed")
    end
  end
end
