# frozen_string_literal: true

require_relative "../spec_helper"
require "aws-sdk-s3"

RSpec.describe PostgresTimeline do
  subject(:postgres_timeline) { described_class.create_with_id(access_key: "dummy-access-key", secret_key: "dummy-secret-key") }

  it "returns ubid as bucket name" do
    expect(postgres_timeline.bucket_name).to eq(postgres_timeline.ubid)
  end

  it "returns walg config" do
    expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")

    walg_config = <<-WALG_CONF
WALG_S3_PREFIX=s3://#{postgres_timeline.ubid}
AWS_ENDPOINT=https://blob-endpoint
AWS_ACCESS_KEY_ID=dummy-access-key
AWS_SECRET_ACCESS_KEY=dummy-secret-key
AWS_REGION: us-east-1
AWS_S3_FORCE_PATH_STYLE=true
PGHOST=/var/run/postgresql
    WALG_CONF

    expect(postgres_timeline.generate_walg_config).to eq(walg_config)
  end

  describe "#need_backup?" do
    let(:sshable) { instance_double(Sshable) }
    let(:leader) {
      instance_double(
        PostgresServer,
        strand: instance_double(Strand, label: "wait"),
        vm: instance_double(Vm, sshable: sshable)
      )
    }

    before do
      allow(postgres_timeline).to receive(:leader).and_return(leader).at_least(:once)
    end

    it "returns false as backup needed if there is no backup endpoint is set" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return(nil)
      expect(postgres_timeline.need_backup?).to be(false)
    end

    it "returns false as backup needed if there is recent backup status check" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")
      expect(postgres_timeline).to receive(:last_ineffective_check_at).and_return(Time.now).twice
      expect(postgres_timeline.need_backup?).to be(false)
    end

    it "returns true as backup needed if there is no backup process or the last backup failed" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint").twice
      expect(postgres_timeline).to receive(:last_ineffective_check_at).and_return(Time.now - 60 * 60).exactly(4).times
      expect(sshable).to receive(:cmd).and_return("NotStarted")
      expect(postgres_timeline.need_backup?).to be(true)

      expect(sshable).to receive(:cmd).and_return("Failed")
      expect(postgres_timeline.need_backup?).to be(true)
    end

    it "returns true as backup needed if previous backup started more than a day ago and is succeeded" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")
      expect(postgres_timeline).to receive(:last_ineffective_check_at).and_return(Time.now - 60 * 60).twice
      expect(postgres_timeline).to receive(:last_backup_started_at).and_return(Time.now - 60 * 60 * 25).twice
      expect(sshable).to receive(:cmd).and_return("Succeeded")
      expect(postgres_timeline.need_backup?).to be(true)
    end

    it "returns false as backup needed if previous backup started less than a day ago" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")
      expect(postgres_timeline).to receive(:last_ineffective_check_at).and_return(Time.now - 60 * 60).twice
      expect(postgres_timeline).to receive(:last_backup_started_at).and_return(Time.now - 60 * 60 * 23).twice
      expect(sshable).to receive(:cmd).and_return("Succeeded")
      expect(postgres_timeline.need_backup?).to be(false)
    end

    it "returns false as backup needed if previous backup started is in progress" do
      expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")
      expect(postgres_timeline).to receive(:last_ineffective_check_at).and_return(Time.now - 60 * 60).twice
      expect(sshable).to receive(:cmd).and_return("InProgress")
      expect(postgres_timeline.need_backup?).to be(false)
    end
  end

  it "returns most recent backup before given target" do
    stub_const("Backup", Struct.new(:last_modified))
    most_recent_backup_time = Time.now
    expect(postgres_timeline).to receive(:backups).and_return(
      [
        instance_double(Backup, key: "basebackups_005/0001_backup_stop_sentinel.json", last_modified: most_recent_backup_time - 200),
        instance_double(Backup, key: "basebackups_005/0002_backup_stop_sentinel.json", last_modified: most_recent_backup_time - 100),
        instance_double(Backup, key: "basebackups_005/0003_backup_stop_sentinel.json", last_modified: most_recent_backup_time)
      ]
    )

    expect(postgres_timeline.last_backup_label_before_target(target: most_recent_backup_time - 50)).to eq("0002")
  end

  it "returns list of backups" do
    expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")

    s3_client = Aws::S3::Client.new(stub_responses: true)
    s3_client.stub_responses(:list_objects_v2, {is_truncated: false, contents: [{key: "backup_stop_sentinel.json"}, {key: "unrelated_file"}]})
    expect(Aws::S3::Client).to receive(:new).and_return(s3_client)

    expect(postgres_timeline.backups.map(&:key)).to eq(["backup_stop_sentinel.json"])
  end

  it "returns blob storage endpoint" do
    expect(Project).to receive(:[]).and_return(instance_double(Project, minio_clusters: [instance_double(MinioCluster, connection_strings: ["https://blob-endpoint"])]))
    expect(postgres_timeline.blob_storage_endpoint).to eq("https://blob-endpoint")
  end

  it "returns nil as blob storage endpoint if no minio cluster is found" do
    expect(Project).to receive(:[]).and_return(instance_double(Project, minio_clusters: []))
    expect(postgres_timeline.blob_storage_endpoint).to be_nil
  end

  it "raises exception if no minio cluster in production" do
    expect(Config).to receive(:production?).and_return(true)
    expect(Project).to receive(:[]).and_return(instance_double(Project, minio_clusters: []))
    expect { postgres_timeline.blob_storage_endpoint }.to raise_error "BUG: Missing blob storage configuration"
  end

  it "returns blob storage client from cache" do
    expect(postgres_timeline).to receive(:blob_storage_endpoint).and_return("https://blob-endpoint")
    expect(MinioClient).to receive(:new).and_return("dummy-client").once
    expect(postgres_timeline.blob_storage_client).to eq("dummy-client")
    expect(postgres_timeline.blob_storage_client).to eq("dummy-client")
  end
end
