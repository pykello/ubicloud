# frozen_string_literal: true

require_relative "../lib/storage_copy"

RSpec.describe StorageCopy do
  let(:source_conf) {
    {"bucket" => "src-bucket", "prefix" => "src/prefix", "region" => "us-east-1",
     "endpoint" => "https://src.example.com", "access_key_id" => "src-ak", "secret_access_key" => "src-sk"}
  }
  let(:target_conf) {
    {"bucket" => "tgt-bucket", "prefix" => "tgt/prefix", "region" => "eu-west-1",
     "endpoint" => "https://tgt.example.com", "access_key_id" => "tgt-ak", "secret_access_key" => "tgt-sk"}
  }
  let(:stats_file) { "/tmp/copy_stats_test.json" }

  it "raises when a required key is missing" do
    expect { described_class.new(source_conf.reject { |k, _| k == "bucket" }, target_conf, stats_file) }
      .to raise_error("missing bucket in source_conf")
  end

  describe "#copy" do
    let(:source_client) { Aws::S3::Client.new(stub_responses: true) }
    let(:target_client) { Aws::S3::Client.new(stub_responses: true) }

    before do
      allow(Aws::S3::Client).to receive(:new) { |args|
        (args[:access_key_id] == "src-ak") ? source_client : target_client
      }
    end

    it "paginates source list, streams each object to target, then writes stats" do
      list_calls = []
      allow(source_client).to receive(:list_objects_v2) { |args|
        list_calls << args
        if list_calls.size == 1
          Aws::S3::Types::ListObjectsV2Output.new(
            contents: [Aws::S3::Types::Object.new(key: "src/prefix/a", size: 5),
              Aws::S3::Types::Object.new(key: "src/prefix/sub/b", size: 7)],
            is_truncated: true, next_continuation_token: "tok",
          )
        else
          Aws::S3::Types::ListObjectsV2Output.new(
            contents: [Aws::S3::Types::Object.new(key: "src/prefix/c", size: 11)],
            is_truncated: false,
          )
        end
      }
      bodies = {"src/prefix/a" => "aaaaa", "src/prefix/sub/b" => "bbbbbbb", "src/prefix/c" => "ccccccccccc"}
      allow(source_client).to receive(:get_object) { |args|
        Aws::S3::Types::GetObjectOutput.new(body: StringIO.new(bodies.fetch(args[:key])))
      }
      put_calls = []
      allow(target_client).to receive(:put_object) { |args| put_calls << args }
      written = nil
      allow(File).to receive(:write).with(stats_file, instance_of(String)) { |_, body| written = JSON.parse(body) }

      described_class.new(source_conf, target_conf, stats_file).copy

      expect(list_calls.map { it[:continuation_token] }).to eq([nil, "tok"])
      expect(put_calls.map { [it[:bucket], it[:key], it[:content_length]] }).to eq([
        ["tgt-bucket", "tgt/prefix/a", 5],
        ["tgt-bucket", "tgt/prefix/sub/b", 7],
        ["tgt-bucket", "tgt/prefix/c", 11],
      ])
      expect(written).to eq("total_bytes" => 23, "total_objects" => 3)
    end
  end
end
