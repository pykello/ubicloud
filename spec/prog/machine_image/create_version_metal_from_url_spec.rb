# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::CreateVersionMetalFromUrl do
  subject(:prog) { described_class.new(strand) }

  let(:vm_host) { create_vm_host }
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
      status: "creating", archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")
  }
  let(:url) { "https://example.com/image.raw" }
  let(:sha256sum) { "abc123" }
  let(:strand) {
    vbb = create_vhost_block_backend(version: "v0.4.1", allocation_weight: 1, vm_host_id: vm_host.id)
    Strand.create_with_id(
      mi_version_metal,
      prog: "MachineImage::CreateVersionMetalFromUrl",
      label: "archive",
      stack: [{
        "subject_id" => mi_version_metal.id,
        "url" => url,
        "sha256sum" => sha256sum,
        "vm_host_id" => vm_host.id,
        "vhost_block_backend_version" => vbb.version,
        "set_as_latest" => false,
      }],
    )
  }

  describe "#archive" do
    let(:sshable) { vm_host.sshable }
    let(:daemon_name) { "archive_#{mi_version.ubid}" }
    let(:stats_path) { "/tmp/archive_stats_#{mi_version.ubid}.json" }

    before do
      allow(prog).to receive(:vm_host).and_return(vm_host)
    end

    it "reads stats, cleans daemon and hops to finish when daemon succeeded" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("Succeeded")
      expect(sshable).to receive(:_cmd).with("cat #{stats_path}").and_return('{"physical_size_bytes": 10485760, "logical_size_bytes": 1073741824}')
      expect(sshable).to receive(:d_clean).with(daemon_name)

      expect { prog.archive }.to hop("finish")
      expect(strand.stack.first["physical_size_bytes"]).to eq(10485760)
      expect(strand.stack.first["logical_size_bytes"]).to eq(1073741824)
    end

    it "cleans daemon, marks status as failed, and pops when daemon failed" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("Failed")
      expect(sshable).to receive(:d_clean).with(daemon_name)
      expect { prog.archive }.to exit({"msg" => "Metal machine image version archive failed"})
      expect(mi_version_metal.reload.status).to eq("failed")
    end

    it "starts daemon when status is NotStarted" do
      expect(sshable).to receive(:d_check).with(daemon_name).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(daemon_name,
        "sudo", "host/bin/archive-url", url, sha256sum, "v0.4.1", stats_path,
        stdin: prog.archive_params_json, log: false)

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
      refresh_frame(prog, new_values: {"physical_size_bytes" => 10 * 1024 * 1024, "logical_size_bytes" => 20 * 1024 * 1024})
      allow(prog).to receive(:vm_host).and_return(vm_host)
      expect(vm_host.sshable).to receive(:_cmd).with("sudo rm -f /tmp/archive_stats_#{mi_version.ubid}.json")
    }

    it "enables machine image version metal and sets archive size" do
      expect { prog.finish }.to exit({"msg" => "Metal machine image version is ready"})

      mi_version_metal.reload
      machine_image.reload
      expect(mi_version_metal.status).to eq("ready")
      expect(mi_version_metal.archive_size_mib).to eq(10)
      expect(mi_version.reload.actual_size_mib).to eq(20)
      expect(BillingRecord.where(resource_id: mi_version_metal.id).count).to eq(1)
    end

    it "sets machine image latest version when configured" do
      refresh_frame(prog, new_values: {"set_as_latest" => true})

      expect { prog.finish }.to exit({"msg" => "Metal machine image version is ready"})

      machine_image.reload
      expect(machine_image.latest_version.id).to eq(mi_version_metal.id)
    end
  end

  describe "#archive_params_json" do
    it "generates JSON payload with store credentials" do
      result = JSON.parse(prog.archive_params_json)

      expect(result["target_conf"]).to include(
        "endpoint" => store.endpoint,
        "region" => store.region,
        "bucket" => store.bucket,
        "prefix" => mi_version_metal.store_prefix,
        "access_key_id" => store.access_key,
        "secret_access_key" => store.secret_key,
        "archive_kek" => archive_kek.secret_key_material_hash,
      )
    end
  end

  describe "#stats_file_path" do
    it "returns the expected path" do
      expect(prog.stats_file_path).to eq("/tmp/archive_stats_#{mi_version.ubid}.json")
    end
  end

  describe "#vm_host" do
    it "returns the vm host from the frame" do
      vm_host = create_vm_host
      refresh_frame(prog, new_values: {"vm_host_id" => vm_host.id})
      expect(prog.vm_host).to eq(vm_host)
    end
  end
end
