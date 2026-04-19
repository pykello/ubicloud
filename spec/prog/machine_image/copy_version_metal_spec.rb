# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::MachineImage::CopyVersionMetal do
  subject(:prog) { described_class.new(strand) }

  let(:project) { Project.create(name: "copy-mi-project") }

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
      label: "copy_objects",
      stack: [{
        "source_machine_image_version_metal_id" => source_mi_version_metal.id,
        "set_as_latest" => false,
      }],
    )
  }

  describe ".assemble" do
    it "creates a target version, metal, kek, and strand" do
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
      expect(target_kek.algorithm).to eq(source_archive_kek.algorithm)
      expect(target_kek.key).to eq(source_archive_kek.key)
      expect(target_kek.init_vector).to eq(source_archive_kek.init_vector)
      expect(target_kek.auth_data).to eq(source_archive_kek.auth_data)

      expect(strand.prog).to eq("MachineImage::CopyVersionMetal")
      expect(strand.label).to eq("copy_objects")
      expect(strand.stack.first["source_machine_image_version_metal_id"]).to eq(source_mi_version_metal.id)
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
  end

  describe "#copy_objects" do
    let(:source_s3) { Aws::S3::Client.new(stub_responses: true) }
    let(:target_s3) { Aws::S3::Client.new(stub_responses: true) }

    before do
      allow(prog).to receive_messages(source_s3_client: source_s3, target_s3_client: target_s3)
    end

    it "copies a single page of objects and hops to finish" do
      source_prefix = source_mi_version_metal.store_prefix
      target_prefix = target_mi_version_metal.store_prefix
      source_s3.stub_responses(:list_objects_v2, {
        contents: [
          {key: "#{source_prefix}/chunk0", size: 5},
          {key: "#{source_prefix}/chunk1", size: 7},
        ],
        is_truncated: false,
      })
      get_results = [
        Aws::S3::Types::GetObjectOutput.new(body: StringIO.new("body0")),
        Aws::S3::Types::GetObjectOutput.new(body: StringIO.new("body1")),
      ]
      expect(source_s3).to receive(:get_object).with(bucket: source_store.bucket, key: "#{source_prefix}/chunk0").and_return(get_results[0])
      expect(source_s3).to receive(:get_object).with(bucket: source_store.bucket, key: "#{source_prefix}/chunk1").and_return(get_results[1])

      expect(target_s3).to receive(:put_object).with(bucket: target_store.bucket, key: "#{target_prefix}/chunk0", body: get_results[0].body, content_length: 5)
      expect(target_s3).to receive(:put_object).with(bucket: target_store.bucket, key: "#{target_prefix}/chunk1", body: get_results[1].body, content_length: 7)

      expect { prog.copy_objects }.to hop("finish")
    end

    it "stores the continuation token and naps when the page is truncated" do
      source_s3.stub_responses(:list_objects_v2, {
        contents: [{key: "#{source_mi_version_metal.store_prefix}/chunk0", size: 1}],
        is_truncated: true,
        next_continuation_token: "next-token",
      })
      allow(source_s3).to receive(:get_object).and_return(
        Aws::S3::Types::GetObjectOutput.new(body: StringIO.new("x")),
      )
      allow(target_s3).to receive(:put_object)

      expect { prog.copy_objects }.to nap(0)

      expect(strand.reload.stack.first["continuation_token"]).to eq("next-token")
    end

    it "passes the continuation token to list_objects_v2 on subsequent invocations" do
      strand.stack.first["continuation_token"] = "saved-token"
      strand.modified!(:stack)
      strand.save_changes
      prog.instance_variable_set(:@frame, nil)

      expect(source_s3).to receive(:list_objects_v2).with(
        bucket: source_store.bucket,
        prefix: source_mi_version_metal.store_prefix,
        max_keys: 100,
        continuation_token: "saved-token",
      ).and_return(Aws::S3::Types::ListObjectsV2Output.new(contents: [], is_truncated: false))

      expect { prog.copy_objects }.to hop("finish")

      expect(strand.reload.stack.first).not_to have_key("continuation_token")
    end
  end

  describe "#finish" do
    it "enables the target metal and copies the archive size" do
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

  describe "#source_machine_image_version_metal" do
    it "returns the source metal from the frame" do
      expect(prog.source_machine_image_version_metal).to eq(source_mi_version_metal)
    end
  end

  describe "S3 client helpers" do
    it "builds source and target clients with the store credentials" do
      expect(Aws::S3::Client).to receive(:new).with(
        access_key_id: source_store.access_key,
        secret_access_key: source_store.secret_key,
        endpoint: source_store.endpoint,
        region: source_store.region,
        force_path_style: true,
        http_open_timeout: 5,
        http_read_timeout: 60,
        retry_limit: 0,
      ).and_return(:source_client)

      expect(Aws::S3::Client).to receive(:new).with(
        access_key_id: target_store.access_key,
        secret_access_key: target_store.secret_key,
        endpoint: target_store.endpoint,
        region: target_store.region,
        force_path_style: true,
        http_open_timeout: 5,
        http_read_timeout: 60,
        retry_limit: 0,
      ).and_return(:target_client)

      expect(prog.source_s3_client).to eq(:source_client)
      expect(prog.target_s3_client).to eq(:target_client)
    end
  end
end
