# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::Minio::MinioPoolNexus do
  subject(:nx) { described_class.new(described_class.assemble(minio_cluster.id, 0)) }

  let(:minio_cluster) {
    MinioCluster.create_with_id(
      location: "hetzner-hel1",
      name: "minio-cluster-name",
      admin_user: "minio-admin",
      admin_password: "dummy-password",
      target_total_storage_size_gib: 100,
      target_total_pool_count: 1,
      target_total_server_count: 1,
      target_total_driver_count: 1,
      target_vm_size: "standard-2",
      private_subnet_id: ps.id
    )
  }
  let(:ps) {
    Prog::Vnet::SubnetNexus.assemble(
      minio_project.id, name: "minio-cluster-name"
    )
  }

  let(:minio_project) { Project.create_with_id(name: "default", provider: "hetzner").tap { _1.associate_with_project(_1) } }

  before do
    allow(minio_cluster).to receive(:projects).and_return([minio_project])
    allow(Config).to receive(:minio_service_project_id).and_return(minio_project.id)
  end

  describe ".assemble" do
    it "creates a minio pool" do
      st = described_class.assemble(minio_cluster.id, 0)
      expect(MinioPool.count).to eq 1
      expect(st.label).to eq "start"
      expect(MinioPool.first.cluster).to eq minio_cluster
    end

    it "fails if cluster is not valid" do
      expect {
        described_class.assemble(SecureRandom.uuid, 0)
      }.to raise_error RuntimeError, "No existing cluster"
    end
  end

  describe "#start" do
    it "creates new minio servers and hops to wait_servers" do
      described_class.assemble(minio_cluster.id, 0)

      expect { nx.start }.to hop("wait_servers")
      expect(MinioServer.count).to eq 1
      expect(MinioServer.first.pool.name).to eq "minio-cluster-name-0"
    end
  end

  describe "#wait_servers" do
    it "waits if nothing to do" do
      st = instance_double(Strand, label: "start")
      ms = instance_double(MinioServer, strand: st)
      expect(nx.minio_pool).to receive(:servers).and_return([ms])
      expect { nx.wait_servers }.to nap(5)
    end

    it "hops to wait if all servers are waiting" do
      st = instance_double(Strand, label: "wait")
      ms = instance_double(MinioServer, strand: st)
      expect(nx.minio_pool).to receive(:servers).and_return([ms])
      expect { nx.wait_servers }.to hop("wait")
    end
  end

  describe "#wait" do
    it "naps" do
      expect { nx.wait }.to nap(30)
    end
  end

  describe "#destroy" do
    it "increments destroy semaphore of minio servers and hops to wait_servers_destroy" do
      expect(nx).to receive(:decr_destroy)
      ms = instance_double(MinioServer)
      expect(ms).to receive(:incr_destroy)
      expect(nx.minio_pool).to receive(:servers).and_return([ms])
      expect { nx.destroy }.to hop("wait_servers_destroyed")
    end
  end

  describe "#wait_servers_destroyed" do
    it "naps if there are still minio servers" do
      expect(nx.minio_pool).to receive(:servers).and_return([true])
      expect { nx.wait_servers_destroyed }.to nap(5)
    end

    it "pops if all minio servers are destroyed" do
      expect(nx.minio_pool).to receive(:servers).and_return([])
      expect(nx.minio_pool).to receive(:destroy)

      expect { nx.wait_servers_destroyed }.to exit({"msg" => "pool destroyed"})
    end
  end

  describe "#before_run" do
    it "hops to destroy if strand is not destroy" do
      st = described_class.assemble(minio_cluster.id, 0)
      st.update(label: "start")
      expect(nx).to receive(:when_destroy_set?).and_yield
      expect { nx.before_run }.to hop("destroy")
    end

    it "does not hop to destroy if strand is destroy" do
      st = described_class.assemble(minio_cluster.id, 0)
      st.update(label: "destroy")
      expect { nx.before_run }.not_to hop("destroy")
    end

    it "does not hop to destroy if destroy is not set" do
      expect(nx).to receive(:when_destroy_set?).and_return(false)
      expect { nx.before_run }.not_to hop("destroy")
    end

    it "does not hop to destroy if strand label is destroy" do
      expect(nx).to receive(:when_destroy_set?).and_yield
      expect(nx.strand).to receive(:label).and_return("destroy")
      expect { nx.before_run }.not_to hop("destroy")
    end
  end
end
