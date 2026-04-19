# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::CopyVersionMetal do
  subject(:prog) { described_class.new(strand) }

  def make_store(loc, label)
    MachineImageStore.create(project_id: project.id, location_id: loc, provider: "minio",
      region: "r", endpoint: "https://#{label}.example.com/", bucket: "#{label}-bucket",
      access_key: "#{label}-ak", secret_key: "#{label}-sk")
  end

  let(:project) { Project.create(name: "p") }
  let(:vm_host) { create_vm_host(location_id: Location::HETZNER_HEL1_ID) }
  let(:source_store) { make_store(Location::HETZNER_FSN1_ID, "src") }
  let(:target_store) { make_store(Location::HETZNER_HEL1_ID, "tgt") }
  let(:source_mi) { MachineImage.create(name: "img", arch: "x64", project_id: project.id, location_id: Location::HETZNER_FSN1_ID) }
  let(:target_mi) { MachineImage.create(name: "img", arch: "x64", project_id: project.id, location_id: Location::HETZNER_HEL1_ID) }
  let(:source_kek) { StorageKeyEncryptionKey.create_random(auth_data: "src-kek") }
  let(:source_miv) { MachineImageVersion.create(machine_image_id: source_mi.id, version: "1.0", actual_size_mib: 5120) }
  let(:source_metal) {
    MachineImageVersionMetal.create_with_id(source_miv, enabled: true, archive_size_mib: 1024,
      archive_kek_id: source_kek.id, store_id: source_store.id, store_prefix: "src/prefix")
  }
  let(:target_kek) { StorageKeyEncryptionKey.create_random(auth_data: "tgt-kek") }
  let(:target_miv) { MachineImageVersion.create(machine_image_id: target_mi.id, version: "1.0") }
  let(:target_metal) {
    MachineImageVersionMetal.create_with_id(target_miv, enabled: false,
      archive_kek_id: target_kek.id, store_id: target_store.id, store_prefix: "tgt/prefix")
  }
  let(:strand) {
    Strand.create_with_id(target_metal, prog: "MachineImage::CopyVersionMetal", label: "copy",
      stack: [{
        "source_machine_image_version_metal_id" => source_metal.id,
        "vm_host_id" => vm_host.id,
        "set_as_latest" => false,
      }])
  }

  describe ".assemble" do
    before { vm_host }

    it "creates the target version, metal with cloned kek material, and strand" do
      st = described_class.assemble(source_metal, target_mi, target_store)
      target = MachineImageVersionMetal[st.id]
      expect(target.enabled).to be false
      expect(target.store_id).to eq(target_store.id)
      expect(target.store_prefix).to eq("#{project.ubid}/#{target_mi.ubid}/1.0")
      expect(target.machine_image_version.actual_size_mib).to eq(source_miv.actual_size_mib)
      kek = target.archive_kek
      expect(kek.id).not_to eq(source_kek.id)
      expect([kek.key, kek.init_vector, kek.auth_data]).to eq([source_kek.key, source_kek.init_vector, source_kek.auth_data])
      expect(st.label).to eq("copy")
      expect(st.stack.first).to include(
        "source_machine_image_version_metal_id" => source_metal.id,
        "vm_host_id" => vm_host.id,
        "set_as_latest" => true,
      )
    end

    it "fails when source not enabled" do
      source_metal.update(enabled: false)
      expect { described_class.assemble(source_metal, target_mi, target_store) }.to raise_error(/not enabled/)
    end

    it "fails when target store and target machine image are in different locations" do
      expect { described_class.assemble(source_metal, target_mi, source_store) }.to raise_error(/same location/)
    end

    it "fails when target machine image already has the same version" do
      MachineImageVersion.create(machine_image_id: target_mi.id, version: "1.0")
      expect { described_class.assemble(source_metal, target_mi, target_store) }.to raise_error("target machine image already has version 1.0")
    end

    it "fails when no vm host exists in target location" do
      vm_host.update(allocation_state: "draining")
      expect { described_class.assemble(source_metal, target_mi, target_store) }.to raise_error(/no vm host/)
    end
  end

  describe "#copy" do
    let(:unit_name) { "copy_#{target_metal.ubid}" }
    let(:stats_path) { "/tmp/copy_stats_#{target_metal.ubid}.json" }
    let(:sshable) { vm_host.sshable }

    it "records stats, cleans daemon, and hops to finish on Succeeded" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("Succeeded")
      expect(sshable).to receive(:_cmd).with("cat #{stats_path}").and_return('{"total_bytes":42}')
      expect(sshable).to receive(:d_clean).with(unit_name)
      expect { prog.copy }.to hop("finish")
      expect(strand.reload.stack.first["total_bytes"]).to eq(42)
    end

    it "restarts daemon and naps on Failed" do
      expect(sshable).to receive(:d_check).and_return("Failed")
      expect(sshable).to receive(:d_restart).with(unit_name)
      expect { prog.copy }.to nap(60)
    end

    it "starts daemon and naps on NotStarted, passing source/target store config via stdin" do
      expect(sshable).to receive(:d_check).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(unit_name, "sudo", "host/bin/copy-archive", stats_path, stdin: prog.copy_params_json, log: false)
      params = JSON.parse(prog.copy_params_json)
      expect(params["source_conf"]).to eq("bucket" => source_store.bucket, "prefix" => source_metal.store_prefix,
        "region" => source_store.region, "endpoint" => source_store.endpoint,
        "access_key_id" => source_store.access_key, "secret_access_key" => source_store.secret_key)
      expect(params["target_conf"]).to eq("bucket" => target_store.bucket, "prefix" => target_metal.store_prefix,
        "region" => target_store.region, "endpoint" => target_store.endpoint,
        "access_key_id" => target_store.access_key, "secret_access_key" => target_store.secret_key)
      expect { prog.copy }.to nap(30)
    end

    it "naps on InProgress" do
      expect(sshable).to receive(:d_check).and_return("InProgress")
      expect { prog.copy }.to nap(30)
    end

    it "logs and naps on unexpected status" do
      expect(sshable).to receive(:d_check).and_return("?")
      expect(Clog).to receive(:emit).with("Unexpected daemonizer2 status: ?")
      expect { prog.copy }.to nap(60)
    end
  end

  describe "#finish" do
    before { expect(vm_host.sshable).to receive(:_cmd).with("sudo rm -f /tmp/copy_stats_#{target_metal.ubid}.json") }

    it "enables target metal, copies archive size, and leaves latest_version_id alone when not set_as_latest" do
      expect { prog.finish }.to exit({"msg" => "Metal machine image version is copied and enabled"})
      expect(target_metal.reload.enabled).to be true
      expect(target_metal.archive_size_mib).to eq(source_metal.archive_size_mib)
      expect(target_mi.reload.latest_version_id).to be_nil
    end

    it "sets latest_version_id when set_as_latest" do
      refresh_frame(prog, new_values: {"set_as_latest" => true})
      expect { prog.finish }.to exit({"msg" => "Metal machine image version is copied and enabled"})
      expect(target_mi.reload.latest_version_id).to eq(target_metal.id)
    end
  end

  it "exposes vm_host and stats_file_path helpers" do
    expect(prog.vm_host).to eq(vm_host)
    expect(prog.stats_file_path).to eq("/tmp/copy_stats_#{target_metal.ubid}.json")
  end
end
