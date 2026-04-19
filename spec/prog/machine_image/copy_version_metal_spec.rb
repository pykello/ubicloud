# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::CopyVersionMetal do
  subject(:prog) { described_class.new(strand) }

  let(:project) { Project.create(name: "copy-mi-project") }

  let(:source_vm_host) { create_vm_host(location_id: Location::HETZNER_FSN1_ID, allocation_state: "accepting") }
  let(:target_vm_host) { create_vm_host(location_id: Location::HETZNER_HEL1_ID, allocation_state: "accepting") }

  let(:source_store) {
    MachineImageStore.create(
      project_id: project.id,
      location_id: Location::HETZNER_FSN1_ID,
      provider: "minio",
      region: "eu",
      endpoint: "https://source.example.com/",
      bucket: "source-bucket",
      access_key: "src-ak",
      secret_key: "src-sk",
    )
  }

  let(:target_store) {
    MachineImageStore.create(
      project_id: project.id,
      location_id: Location::HETZNER_HEL1_ID,
      provider: "minio",
      region: "fi",
      endpoint: "https://target.example.com/",
      bucket: "target-bucket",
      access_key: "tgt-ak",
      secret_key: "tgt-sk",
    )
  }

  let(:source_machine_image) {
    MachineImage.create(name: "test-image", arch: "x64", project_id: project.id, location_id: Location::HETZNER_FSN1_ID)
  }

  let(:target_machine_image) {
    MachineImage.create(name: "test-image", arch: "x64", project_id: project.id, location_id: Location::HETZNER_HEL1_ID)
  }

  let(:source_archive_kek) {
    StorageKeyEncryptionKey.create_random(auth_data: "machine_image_version_source_v1")
  }

  let(:source_mi_version) {
    MachineImageVersion.create(
      machine_image_id: source_machine_image.id,
      version: "1.0",
      actual_size_mib: 5120,
    )
  }

  let(:source_mi_version_metal) {
    MachineImageVersionMetal.create_with_id(
      source_mi_version,
      enabled: true,
      archive_size_mib: 1024,
      archive_kek_id: source_archive_kek.id,
      store_id: source_store.id,
      store_prefix: "#{project.ubid}/#{source_machine_image.ubid}/1.0",
    )
  }

  let(:target_mi_version) {
    MachineImageVersion.create(
      machine_image_id: target_machine_image.id,
      version: "1.0",
      actual_size_mib: 5120,
    )
  }

  let(:target_archive_kek) {
    StorageKeyEncryptionKey.create(
      algorithm: source_archive_kek.algorithm,
      key: source_archive_kek.key,
      init_vector: source_archive_kek.init_vector,
      auth_data: source_archive_kek.auth_data,
    )
  }

  let(:target_mi_version_metal) {
    MachineImageVersionMetal.create_with_id(
      target_mi_version,
      enabled: false,
      archive_kek_id: target_archive_kek.id,
      store_id: target_store.id,
      store_prefix: "#{project.ubid}/#{target_machine_image.ubid}/1.0",
    )
  }

  let(:strand) {
    Strand.create_with_id(
      target_mi_version_metal,
      prog: "MachineImage::CopyVersionMetal",
      label: "copy",
      stack: [{
        "source_machine_image_version_metal_id" => source_mi_version_metal.id,
        "vm_host_id" => target_vm_host.id,
        "set_as_latest" => false,
      }],
    )
  }

  describe ".assemble" do
    before { target_vm_host }

    it "creates a target version, metal, kek, and strand referencing a host in the target location" do
      strand = described_class.assemble(source_mi_version_metal, target_machine_image, target_store)

      target_metal = MachineImageVersionMetal[strand.id]
      expect(target_metal).not_to be_nil
      expect(target_metal.enabled).to be false
      expect(target_metal.store_id).to eq(target_store.id)
      expect(target_metal.store_prefix).to eq("#{project.ubid}/#{target_machine_image.ubid}/1.0")

      target_miv = target_metal.machine_image_version
      expect(target_miv.machine_image_id).to eq(target_machine_image.id)
      expect(target_miv.version).to eq("1.0")
      expect(target_miv.actual_size_mib).to eq(source_mi_version.actual_size_mib)

      target_kek = target_metal.archive_kek
      expect(target_kek.id).not_to eq(source_archive_kek.id)
      expect(target_kek.key).to eq(source_archive_kek.key)
      expect(target_kek.init_vector).to eq(source_archive_kek.init_vector)
      expect(target_kek.auth_data).to eq(source_archive_kek.auth_data)

      expect(strand.prog).to eq("MachineImage::CopyVersionMetal")
      expect(strand.label).to eq("copy")
      expect(strand.stack.first["source_machine_image_version_metal_id"]).to eq(source_mi_version_metal.id)
      expect(strand.stack.first["vm_host_id"]).to eq(target_vm_host.id)
      expect(strand.stack.first["set_as_latest"]).to be true
    end

    it "fails when the source version is not enabled" do
      source_mi_version_metal.update(enabled: false)

      expect {
        described_class.assemble(source_mi_version_metal, target_machine_image, target_store)
      }.to raise_error("source machine image version is not enabled")
    end

    it "fails when target store and target machine image are in different locations" do
      mismatched_store = MachineImageStore.create(
        project_id: project.id,
        location_id: Location::HETZNER_FSN1_ID,
        provider: "minio", region: "eu",
        endpoint: "https://mismatch.example.com/",
        bucket: "mismatch", access_key: "ak", secret_key: "sk",
      )

      expect {
        described_class.assemble(source_mi_version_metal, target_machine_image, mismatched_store)
      }.to raise_error("target store is not in the same location as target machine image")
    end

    it "fails when target machine image already has the same version" do
      MachineImageVersion.create(
        machine_image_id: target_machine_image.id,
        version: source_mi_version.version,
        actual_size_mib: 1,
      )

      expect {
        described_class.assemble(source_mi_version_metal, target_machine_image, target_store)
      }.to raise_error("target machine image already has version 1.0")
    end

    it "fails when no vm host exists in the target location" do
      target_vm_host.update(allocation_state: "draining")

      expect {
        described_class.assemble(source_mi_version_metal, target_machine_image, target_store)
      }.to raise_error("no vm host found in target location")
    end
  end

  describe "#copy" do
    let(:sshable) { target_vm_host.sshable }
    let(:unit_name) { "copy_#{target_mi_version_metal.ubid}" }
    let(:stats_path) { "/tmp/copy_stats_#{target_mi_version_metal.ubid}.json" }

    before do
      allow(prog).to receive(:vm_host).and_return(target_vm_host)
    end

    it "reads stats, cleans daemon, and hops to finish when daemon succeeded" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("Succeeded")
      expect(sshable).to receive(:_cmd).with("cat #{stats_path}").and_return('{"total_bytes": 12345, "total_objects": 7}')
      expect(sshable).to receive(:d_clean).with(unit_name)

      expect { prog.copy }.to hop("finish")

      expect(strand.reload.stack.first["total_bytes"]).to eq(12345)
    end

    it "restarts daemon when it failed" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("Failed")
      expect(sshable).to receive(:d_restart).with(unit_name)
      expect { prog.copy }.to nap(60)
    end

    it "starts daemon when status is NotStarted" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("NotStarted")
      expect(sshable).to receive(:d_run).with(unit_name,
        "sudo", "host/bin/copy-archive", stats_path,
        stdin: prog.copy_params_json, log: false)

      expect { prog.copy }.to nap(30)
    end

    it "naps when daemon is in progress" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("InProgress")
      expect { prog.copy }.to nap(30)
    end

    it "logs and naps on unexpected daemon status" do
      expect(sshable).to receive(:d_check).with(unit_name).and_return("UnknownStatus")
      expect(Clog).to receive(:emit).with("Unexpected daemonizer2 status: UnknownStatus")
      expect { prog.copy }.to nap(60)
    end
  end

  describe "#finish" do
    before do
      allow(prog).to receive(:vm_host).and_return(target_vm_host)
      expect(target_vm_host.sshable).to receive(:_cmd).with("sudo rm -f /tmp/copy_stats_#{target_mi_version_metal.ubid}.json")
    end

    it "enables the target metal and copies the archive size from the source" do
      expect { prog.finish }.to exit({"msg" => "Metal machine image version is copied and enabled"})

      target_mi_version_metal.reload
      expect(target_mi_version_metal.enabled).to be true
      expect(target_mi_version_metal.archive_size_mib).to eq(source_mi_version_metal.archive_size_mib)
    end

    it "sets target machine image latest version when configured" do
      refresh_frame(prog, new_values: {"set_as_latest" => true})

      expect { prog.finish }.to exit({"msg" => "Metal machine image version is copied and enabled"})

      target_machine_image.reload
      expect(target_machine_image.latest_version_id).to eq(target_mi_version_metal.id)
    end
  end

  describe "#copy_params_json" do
    it "includes both source and target store credentials and prefixes" do
      result = JSON.parse(prog.copy_params_json)

      expect(result["source_conf"]).to eq(
        "bucket" => source_store.bucket,
        "prefix" => source_mi_version_metal.store_prefix,
        "region" => source_store.region,
        "endpoint" => source_store.endpoint,
        "access_key_id" => source_store.access_key,
        "secret_access_key" => source_store.secret_key,
      )

      expect(result["target_conf"]).to eq(
        "bucket" => target_store.bucket,
        "prefix" => target_mi_version_metal.store_prefix,
        "region" => target_store.region,
        "endpoint" => target_store.endpoint,
        "access_key_id" => target_store.access_key,
        "secret_access_key" => target_store.secret_key,
      )
    end
  end

  describe "#vm_host" do
    it "returns the vm host from the frame" do
      expect(prog.vm_host).to eq(target_vm_host)
    end
  end

  describe "#stats_file_path" do
    it "returns the expected path" do
      expect(prog.stats_file_path).to eq("/tmp/copy_stats_#{target_mi_version_metal.ubid}.json")
    end
  end
end
