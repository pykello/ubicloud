# frozen_string_literal: true

require_relative "../lib/storage_copy"

RSpec.describe StorageCopy do
  let(:source_conf) {
    {
      "bucket" => "src-bucket",
      "prefix" => "src/prefix",
      "region" => "us-east-1",
      "endpoint" => "https://src.example.com",
      "access_key_id" => "src-ak",
      "secret_access_key" => "src-sk",
    }
  }

  let(:target_conf) {
    {
      "bucket" => "tgt-bucket",
      "prefix" => "tgt/prefix",
      "region" => "eu-west-1",
      "endpoint" => "https://tgt.example.com",
      "access_key_id" => "tgt-ak",
      "secret_access_key" => "tgt-sk",
    }
  }

  let(:stats_file) { "/tmp/copy_stats_test.json" }

  describe "#initialize" do
    it "fails when source_conf is missing a required key" do
      bad_source = source_conf.dup
      bad_source.delete("bucket")

      expect {
        described_class.new(bad_source, target_conf, stats_file)
      }.to raise_error("missing bucket in source_conf")
    end

    it "fails when target_conf is missing a required key" do
      bad_target = target_conf.dup
      bad_target.delete("endpoint")

      expect {
        described_class.new(source_conf, bad_target, stats_file)
      }.to raise_error("missing endpoint in target_conf")
    end
  end

  describe "#copy" do
    let(:source_client) { Aws::S3::Client.new(stub_responses: true) }
    let(:target_client) { Aws::S3::Client.new(stub_responses: true) }
    let(:copier) { described_class.new(source_conf, target_conf, stats_file) }

    before do
      allow(described_class).to receive(:build_client).with(source_conf).and_return(source_client)
      allow(described_class).to receive(:build_client).with(target_conf).and_return(target_client)
    end

    it "copies all objects across pages, then writes stats" do
      source_client.stub_responses(:list_objects_v2, [
        {
          contents: [
            {key: "src/prefix/chunk0", size: 5},
            {key: "src/prefix/chunk1", size: 7},
          ],
          is_truncated: true,
          next_continuation_token: "tok",
        },
        {
          contents: [{key: "src/prefix/sub/chunk2", size: 11}],
          is_truncated: false,
        },
      ])

      get_bodies = {
        "src/prefix/chunk0" => StringIO.new("aaaaa"),
        "src/prefix/chunk1" => StringIO.new("bbbbbbb"),
        "src/prefix/sub/chunk2" => StringIO.new("ccccccccccc"),
      }
      allow(source_client).to receive(:get_object) { |args|
        Aws::S3::Types::GetObjectOutput.new(body: get_bodies.fetch(args[:key]))
      }

      put_calls = []
      allow(target_client).to receive(:put_object) { |args| put_calls << args }

      written_stats = nil
      allow(File).to receive(:write).with(stats_file, instance_of(String)) { |_, body|
        written_stats = JSON.parse(body)
      }

      copier.copy

      expect(put_calls.map { it[:key] }).to eq([
        "tgt/prefix/chunk0",
        "tgt/prefix/chunk1",
        "tgt/prefix/sub/chunk2",
      ])
      expect(put_calls.map { it[:bucket] }.uniq).to eq(["tgt-bucket"])
      expect(put_calls.map { it[:content_length] }).to eq([5, 7, 11])
      expect(written_stats).to eq("total_bytes" => 23, "total_objects" => 3)
    end

    it "passes the continuation token to subsequent list calls" do
      list_calls = []
      allow(source_client).to receive(:list_objects_v2) { |args|
        list_calls << args
        if list_calls.size == 1
          Aws::S3::Types::ListObjectsV2Output.new(
            contents: [],
            is_truncated: true,
            next_continuation_token: "next-token",
          )
        else
          Aws::S3::Types::ListObjectsV2Output.new(contents: [], is_truncated: false)
        end
      }
      allow(File).to receive(:write)

      copier.copy

      expect(list_calls[0]).to eq(bucket: "src-bucket", prefix: "src/prefix", max_keys: 1000)
      expect(list_calls[1]).to eq(bucket: "src-bucket", prefix: "src/prefix", max_keys: 1000, continuation_token: "next-token")
    end
  end

  describe ".build_client" do
    it "constructs an Aws::S3::Client with credentials and endpoint" do
      expect(Aws::S3::Client).to receive(:new).with(
        access_key_id: "src-ak",
        secret_access_key: "src-sk",
        endpoint: "https://src.example.com",
        region: "us-east-1",
        force_path_style: true,
        http_open_timeout: 5,
        http_read_timeout: 60,
        retry_limit: 3,
      ).and_return(:client)

      expect(described_class.build_client(source_conf)).to eq(:client)
    end
  end
end
