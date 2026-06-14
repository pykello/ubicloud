# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::VersionMetalNexus do
  subject(:prog) { described_class.new(strand) }

  let(:project) { Project.create(name: "p") }
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
  let(:mi_version) { MachineImageVersion.create(machine_image_id: machine_image.id, version: "1.0", actual_size_mib: nil) }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "k") }
  let(:mi_version_metal) {
    MachineImageVersionMetal.create_with_id(mi_version,
      status: "creating", archive_kek_id: archive_kek.id, store_id: store.id,
      store_prefix: "#{project.ubid}/#{machine_image.ubid}/1.0")
  }
  let(:strand) {
    Strand.create_with_id(mi_version_metal,
      prog: "MachineImage::VersionMetalNexus", label: "wait", stack: [{}])
  }

  describe ".assemble_from_vm" do
    it "validates the source VM and creates a strand at archive" do
      vhost_block_backend
      s = described_class.assemble_from_vm(machine_image, "1.0", source_vm, store, destroy_source_after: true)
      expect(s.label).to eq("archive")
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
    it "creates a strand at archive with the picked vbb host" do
      vhost_block_backend
      s = described_class.assemble_from_url(machine_image, "2.0", "https://x/img", "abc", store)
      expect(s.label).to eq("archive")
      expect(s.stack.first.values_at("url", "sha256sum", "vm_host_id", "vhost_block_backend_version"))
        .to eq(["https://x/img", "abc", vm_host.id, "v0.4.1"])
    end

    it "raises when no vm host supports archive in the location" do
      expect {
        described_class.assemble_from_url(machine_image, "2.0", "https://x/img", "abc", store)
      }.to raise_error("no vm host with archive support found in location")
    end
  end

  shared_examples "an #archive label" do
    it "hops to finish on Succeeded, capturing stats" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("Succeeded")
      expect(sshable).to receive(:_cmd).with("cat /tmp/archive_stats_#{mi_version.ubid}.json")
        .and_return('{"physical_size_bytes": 10485760, "logical_size_bytes": 1073741824}')
      expect(sshable).to receive(:d_clean).with(daemon)
      expect { archive_prog.archive }.to hop("finish")
      expect(archive_strand.stack.first["physical_size_bytes"]).to eq(10485760)
      expect(archive_strand.stack.first["logical_size_bytes"]).to eq(1073741824)
    end

    it "cleans daemon, flips to failed, and hops to destroy_objects on Failed" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("Failed")
      expect(sshable).to receive(:d_clean).with(daemon)
      expect { archive_prog.archive }.to hop("destroy_objects")
      expect(mi_version_metal.reload.status).to eq("failed")
    end

    it "naps on InProgress" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("InProgress")
      expect { archive_prog.archive }.to nap(30)
    end

    it "logs and naps on unexpected daemon state" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("Unknown")
      expect(Clog).to receive(:emit).with("Unexpected daemonizer2 status: Unknown").and_call_original
      expect { archive_prog.archive }.to nap(60)
    end
  end

  describe "#archive (VM source)" do
    let(:archive_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "archive",
        stack: [{"source_vm_id" => source_vm.id, "destroy_source_after" => false, "set_as_latest" => true}])
    }
    let(:archive_prog) { described_class.new(archive_strand) }
    let(:sshable) { vm_host.sshable }
    let(:daemon) { "archive_#{mi_version.ubid}" }

    def stub_archive_helpers(p)
      allow(p).to receive_messages(source_vm:, vm_host:, archive_params: "{}")
    end

    before { stub_archive_helpers(archive_prog) }

    it_behaves_like "an #archive label"

    it "starts archive-storage-volume daemon on NotStarted" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(daemon,
        "sudo", "host/bin/archive-storage-volume", source_vm.inhost_name, "vda", 0, vhost_block_backend.version,
        "/tmp/archive_stats_#{mi_version.ubid}.json", stdin: "{}", log: false)
      expect { archive_prog.archive }.to nap(30)
    end
  end

  describe "#archive (URL source)" do
    let(:archive_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "archive",
        stack: [{"url" => "https://x/img", "sha256sum" => "abc",
                 "vm_host_id" => vm_host.id, "vhost_block_backend_version" => "v0.4.1",
                 "set_as_latest" => true}])
    }
    let(:archive_prog) { described_class.new(archive_strand) }
    let(:sshable) { vm_host.sshable }
    let(:daemon) { "archive_#{mi_version.ubid}" }

    def stub_archive_helpers(p)
      allow(p).to receive_messages(vm_host:, archive_params: "{}")
    end

    before { stub_archive_helpers(archive_prog) }

    it_behaves_like "an #archive label"

    it "starts archive-url daemon on NotStarted" do
      expect(sshable).to receive(:d_check).with(daemon).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(daemon,
        "sudo", "host/bin/archive-url", "https://x/img", "abc", "v0.4.1",
        "/tmp/archive_stats_#{mi_version.ubid}.json", stdin: "{}", log: false)
      expect { archive_prog.archive }.to nap(30)
    end
  end

  describe "#finish" do
    let(:fin_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "finish",
        stack: [{"source_vm_id" => source_vm.id, "destroy_source_after" => false, "set_as_latest" => true,
                 "physical_size_bytes" => 10 * 1048576, "logical_size_bytes" => 100 * 1048576}])
    }
    let(:fin_prog) { described_class.new(fin_strand) }

    before do
      allow(fin_prog).to receive_messages(source_vm:, vm_host:)
      expect(vm_host.sshable).to receive(:_cmd).with("sudo rm -f /tmp/archive_stats_#{mi_version.ubid}.json")
    end

    it "marks ready, sizes from stats, billing, latest, hops to wait" do
      expect { fin_prog.finish }.to hop("wait")
      expect(mi_version_metal.reload).to have_attributes(status: "ready", archive_size_mib: 10)
      expect(mi_version.reload.actual_size_mib).to eq(100)
      expect(BillingRecord.where(resource_id: mi_version_metal.id).count).to eq(1)
      expect(machine_image.reload.latest_version_id).to eq(mi_version_metal.id)
    end

    it "kicks source VM destroy when destroy_source_after" do
      refresh_frame(fin_prog, new_values: {"destroy_source_after" => true})
      expect { fin_prog.finish }.to hop("wait")
        .and change { source_vm.reload.destroy_set? }.from(false).to(true)
    end
  end

  describe "#wait" do
    before { mi_version_metal.update(status: "ready", archive_size_mib: 1) }

    it "naps when no destroy" do
      expect { prog.wait }.to nap(6 * 60 * 60)
    end
  end

  describe "#destroy" do
    let(:pd_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "destroy", stack: [{}])
    }
    let(:pd_prog) { described_class.new(pd_strand) }

    it "flips status, finalizes billing, reassigns latest, hops to wait_vms" do
      mi_version_metal.update(status: "ready", archive_size_mib: 1)
      machine_image.update(latest_version_id: mi_version.id)
      br = mi_version_metal.create_billing_record
      br.update(span: Sequel.pg_range((Time.now - 60)..))

      expect { pd_prog.destroy }.to hop("wait_vms")
        .and change { mi_version_metal.reload.status }.from("ready").to("destroying")
        .and change { br.reload.span.end }.from(nil).to(be_within(60).of(Time.now))
      expect(machine_image.reload.latest_version_id).to be_nil
    end

    it "is idempotent when already destroying" do
      mi_version_metal.update(status: "destroying")
      expect { pd_prog.destroy }.to hop("wait_vms")
    end

    it "flips a 'failed' row to 'destroying'" do
      mi_version_metal.update(status: "failed", archive_size_mib: nil)
      expect { pd_prog.destroy }.to hop("wait_vms")
      expect(mi_version_metal.reload.status).to eq("destroying")
    end

    it "stops and cleans the archive daemon when status is creating" do
      mi_version_metal.update(status: "creating")
      sshable = vm_host.sshable
      allow(pd_prog).to receive(:vm_host).and_return(vm_host)
      expect(sshable).to receive(:d_stop).with("archive_#{mi_version.ubid}")
      expect(sshable).to receive(:d_check).with("archive_#{mi_version.ubid}").and_return("Failed")
      expect(sshable).to receive(:d_clean).with("archive_#{mi_version.ubid}")
      expect { pd_prog.destroy }.to hop("wait_vms")
    end

    it "skips d_clean when the archive daemon was never started" do
      mi_version_metal.update(status: "creating")
      sshable = vm_host.sshable
      allow(pd_prog).to receive(:vm_host).and_return(vm_host)
      expect(sshable).to receive(:d_stop).with("archive_#{mi_version.ubid}")
      expect(sshable).to receive(:d_check).with("archive_#{mi_version.ubid}").and_return("NotStarted")
      expect(sshable).not_to receive(:d_clean)
      expect { pd_prog.destroy }.to hop("wait_vms")
    end
  end

  describe "destroy dispatch via before_run" do
    it "routes a waiting strand into #destroy on incr_destroy" do
      mi_version_metal.update(status: "ready", archive_size_mib: 1)
      strand
      mi_version_metal.incr_destroy
      hop = strand.unsynchronized_run
      expect(hop).to be_a(Prog::Base::Hop)
      expect(strand.reload.label).to eq("destroy")
      expect(Semaphore.where(strand_id: mi_version_metal.id, name: "destroying").count).to eq(1)
    end

    it "routes an archiving strand into #destroy on incr_destroy" do
      archive_strand = Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "archive",
        stack: [{"source_vm_id" => source_vm.id, "destroy_source_after" => false,
                 "set_as_latest" => true, "archive_failures" => 0}])
      mi_version_metal.incr_destroy
      hop = archive_strand.unsynchronized_run
      expect(hop).to be_a(Prog::Base::Hop)
      expect(archive_strand.reload.label).to eq("destroy")
      expect(Semaphore.where(strand_id: mi_version_metal.id, name: "destroying").count).to eq(1)
    end
  end

  describe "#wait_vms" do
    before { mi_version_metal.update(status: "destroying") }

    it "naps while a VM still references the MIV" do
      other_vm = create_vm(vm_host_id: vm_host.id, project_id: project.id, name: "other")
      sd = StorageDevice.create(name: "sdb", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
      VmStorageVolume.create(
        vm_id: other_vm.id, boot: true, size_gib: 1, disk_index: 0,
        storage_device_id: sd.id, vhost_block_backend_id: vhost_block_backend.id,
        key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "kk").id,
        machine_image_version_id: mi_version.id, vring_workers: 1,
      )
      wv = Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "wait_vms", stack: [{}])
      expect { described_class.new(wv).wait_vms }.to nap(30)
    end

    it "hops to destroy_objects when no VM references the MIV" do
      wv = Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "wait_vms", stack: [{}])
      expect { described_class.new(wv).wait_vms }.to hop("destroy_objects")
    end
  end

  describe "#destroy_objects" do
    let(:s3) { Aws::S3::Client.new(stub_responses: true) }
    let(:do_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "destroy_objects", stack: [{}])
    }
    let(:do_prog) { described_class.new(do_strand) }

    before do
      mi_version_metal.update(status: "destroying")
      allow(Aws::S3::Client).to receive(:new).and_return(s3)
    end

    it "hops to update_database when no objects remain (status=destroying)" do
      s3.stub_responses(:list_objects_v2, {contents: [], is_truncated: false})
      expect { do_prog.destroy_objects }.to hop("update_database")
    end

    it "hops to wait when no objects remain and status=failed (auto-cleanup)" do
      mi_version_metal.update(status: "failed", archive_size_mib: nil)
      s3.stub_responses(:list_objects_v2, {contents: [], is_truncated: false})
      expect { do_prog.destroy_objects }.to hop("wait")
    end

    it "deletes a page and naps" do
      s3.stub_responses(:list_objects_v2, {contents: [{key: "a"}, {key: "b"}], is_truncated: true})
      expect(s3).to receive(:delete_objects).with(bucket: store.bucket,
        delete: {objects: [{key: "a"}, {key: "b"}]}).and_call_original
      expect { do_prog.destroy_objects }.to nap(0)
    end

    it "logs and naps 30 on per-object errors" do
      s3.stub_responses(:list_objects_v2, {contents: [{key: "a"}], is_truncated: false})
      expect(s3).to receive(:delete_objects).and_return(
        Aws::S3::Types::DeleteObjectsOutput.new(deleted: [],
          errors: [Aws::S3::Types::Error.new(key: "a", code: "AccessDenied", message: "no")]),
      )
      expect(Clog).to receive(:emit).with("Failed to delete some machine image archive objects",
        hash_including(count: 1)).and_call_original
      expect { do_prog.destroy_objects }.to nap(30)
    end
  end

  describe "#update_database" do
    let(:ud_strand) {
      Strand.create_with_id(mi_version_metal,
        prog: "MachineImage::VersionMetalNexus", label: "update_database", stack: [{}])
    }
    let(:ud_prog) { described_class.new(ud_strand) }

    it "destroys the metal, kek, and version when status=destroying" do
      mi_version_metal.update(status: "destroying")
      expect { ud_prog.update_database }.to exit({"msg" => "Metal machine image version is destroyed"})
        .and change { mi_version_metal.exists? }.from(true).to(false)
        .and change { archive_kek.exists? }.from(true).to(false)
        .and change { mi_version.exists? }.from(true).to(false)
    end
  end
end
