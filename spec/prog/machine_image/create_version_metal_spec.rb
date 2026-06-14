# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::CreateVersionMetal do
  subject(:prog) { described_class.new(strand) }

  let(:project) { Project.create(name: "test-mi-project") }
  let(:vm_host) { create_vm_host }
  let(:vhost_block_backend) { create_vhost_block_backend(allocation_weight: 50, vm_host_id: vm_host.id) }
  let(:source_vm) {
    vm = create_vm(vm_host_id: vm_host.id, project_id: project.id)
    Strand.create_with_id(vm, prog: "Vm::Nexus", label: "stopped")
    sd = StorageDevice.create(name: "vda", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
    VmStorageVolume.create(
      vm_id: vm.id, boot: true, size_gib: 5, disk_index: 0,
      storage_device_id: sd.id, vhost_block_backend_id: vhost_block_backend.id,
      key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "test-source-kek").id,
      vring_workers: 1, track_written: true,
    )
    vm
  }
  let(:source_vol) { source_vm.vm_storage_volumes.first }
  let(:source_kek) { source_vol.key_encryption_key_1 }
  let(:machine_image) { MachineImage.create(name: "test-image", arch: "x64", project_id: project.id, location_id: Location::HETZNER_FSN1_ID) }
  let(:store) {
    MachineImageStore.create(
      project_id: project.id,
      location_id: Location::HETZNER_FSN1_ID,
      provider: "minio",
      region: "eu",
      endpoint: "https://minio.example.com/",
      bucket: "test-bucket",
      access_key: "test-access-key",
      secret_key: "test-secret-key",
    )
  }
  let(:mi_version) {
    MachineImageVersion.create(
      machine_image_id: machine_image.id,
      version: "1.0",
      actual_size_mib: 5120,
    )
  }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "target-kek") }
  let(:mi_version_metal) {
    MachineImageVersionMetal.create_with_id(
      mi_version,
      status: "creating",
      archive_kek_id: archive_kek.id,
      store_id: store.id,
      store_prefix: "#{project.ubid}/#{machine_image.ubid}/1.0",
    )
  }
  let(:strand) {
    Strand.create_with_id(
      mi_version_metal,
      prog: "MachineImage::CreateVersionMetal",
      label: "archive",
      stack: [{
        "source_vm_id" => source_vm.id,
        "destroy_source_after" => false,
      }],
    )
  }

  describe ".assemble" do
    it "is deprecated and raises" do
      expect { described_class.assemble }.to raise_error(MachineImageError, /temporarily unavailable/)
    end
  end

  describe "#archive" do
    let(:sshable) { source_vm.vm_host.sshable }
    let(:daemon_name) { "archive_#{mi_version.ubid}" }
    let(:stats_path) { "/tmp/archive_stats_#{mi_version.ubid}.json" }

    before do
      allow(prog).to receive_messages(archive_params_json: "{\"field\":\"value\"}", source_vm:)
    end

    it "reads stats, cleans daemon and hops to finish when daemon succeeded" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("Succeeded")
      expect(sshable).to receive(:_cmd).with("cat #{stats_path}").and_return('{"physical_size_bytes": 10485760, "logical_size_bytes": 1073741824}')
      expect(sshable).to receive(:d_clean).with(daemon_name)

      expect { prog.archive }.to hop("finish")
      expect(strand.stack.first["archive_size_bytes"]).to eq(10485760)
    end

    it "restarts daemon when it failed" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("Failed")
      expect(sshable).to receive(:d_restart).with(daemon_name)
      expect { prog.archive }.to nap(60)
    end

    it "starts daemon when status is NotStarted" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(daemon_name,
        "sudo", "host/bin/archive-storage-volume", source_vm.inhost_name, "vda", 0, vhost_block_backend.version, stats_path,
        stdin: "{\"field\":\"value\"}", log: false)

      expect { prog.archive }.to nap(30)
    end

    it "naps when daemon is still running" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("InProgress")

      expect { prog.archive }.to nap(30)
    end

    it "handles unexpected daemon status" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("UnknownStatus")
      expect(Clog).to receive(:emit).with("Unexpected daemonizer2 status: UnknownStatus")

      expect { prog.archive }.to nap(60)
    end
  end

  describe "#finish" do
    before {
      refresh_frame(prog, new_values: {"archive_size_bytes" => 10 * 1024 * 1024})
      allow(prog).to receive(:source_vm).and_return(source_vm)
      expect(source_vm.vm_host.sshable).to receive(:_cmd).with("sudo rm -f /tmp/archive_stats_#{mi_version.ubid}.json")
    }

    it "enables machine image version metal and sets archive size" do
      expect { prog.finish }.to exit({"msg" => "Metal machine image version is ready"})

      mi_version_metal.reload
      mi_version.reload
      machine_image.reload
      expect(mi_version_metal.status).to eq("ready")
      expect(mi_version_metal.archive_size_mib).to eq(10)
      expect(BillingRecord.where(resource_id: mi_version_metal.id).count).to eq(1)
    end

    it "destroys source vm when configured" do
      refresh_frame(prog, new_values: {"archive_size_bytes" => 10 * 1024 * 1024, "destroy_source_after" => true})

      expect { prog.finish }.to exit({"msg" => "Metal machine image version is ready"})

      expect(source_vm.reload.destroy_set?).to be true
    end

    it "sets machine image latest version when configured" do
      refresh_frame(prog, new_values: {"archive_size_bytes" => 10 * 1024 * 1024, "set_as_latest" => true})

      expect { prog.finish }.to exit({"msg" => "Metal machine image version is ready"})

      machine_image.reload
      expect(machine_image.latest_version.id).to eq(mi_version_metal.id)
    end
  end

  describe "#archive_params_json" do
    it "generates JSON payload with store credentials" do
      allow(Vm).to receive(:[]).with(source_vm.id).and_return(source_vm)

      result = JSON.parse(prog.archive_params_json)

      expect(result["kek"]).to eq(source_kek.secret_key_material_hash)
      expect(result["target_conf"]).to include(
        "endpoint" => store.endpoint,
        "region" => store.region,
        "bucket" => store.bucket,
        "prefix" => mi_version_metal.store_prefix,
        "access_key_id" => store.access_key,
        "secret_access_key" => store.secret_key,
        "archive_kek" => archive_kek.secret_key_material_hash,
      )
      expect(result).not_to have_key("vm_name")
      expect(result).not_to have_key("device")
      expect(result).not_to have_key("disk_index")
      expect(result).not_to have_key("vhost_block_backend_version")
    end
  end

  describe "#stats_file_path" do
    it "returns the expected path" do
      expect(prog.stats_file_path).to eq("/tmp/archive_stats_#{mi_version.ubid}.json")
    end
  end
end
