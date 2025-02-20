# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::Postgres::PostgresResourceNexus do
  subject(:nx) { described_class.new(Strand.new(id: "8148ebdf-66b8-8ed0-9c2f-8cfe93f5aa77")) }

  let(:postgres_resource) {
    instance_double(
      PostgresResource,
      ubid: "pgnjbsrja7ka4nk7ptcg03szg2",
      location: "hetzner-hel1",
      root_cert_1: "root cert 1",
      root_cert_key_1: nil,
      root_cert_2: "root cert 2",
      root_cert_key_2: nil,
      server_cert: "server cert",
      server_cert_key: nil,
      server: instance_double(
        PostgresServer,
        vm: instance_double(
          Vm,
          cores: 1
        )
      )
    ).as_null_object
  }

  before do
    allow(nx).to receive(:postgres_resource).and_return(postgres_resource)
  end

  describe ".assemble" do
    let(:customer_project) { Project.create_with_id(name: "default", provider: "hetzner").tap { _1.associate_with_project(_1) } }
    let(:postgres_project) { Project.create_with_id(name: "default", provider: "hetzner").tap { _1.associate_with_project(_1) } }

    it "validates input" do
      expect(Config).to receive(:postgres_service_project_id).and_return(postgres_project.id).at_least(:once)

      expect {
        described_class.assemble(project_id: "26820e05-562a-4e25-a51b-de5f78bd00af", location: "hetzner-hel1", server_name: "pg-server-name", target_vm_size: "standard-2", target_storage_size_gib: 100)
      }.to raise_error RuntimeError, "No existing project"

      expect {
        described_class.assemble(project_id: customer_project.id, location: "hetzner-xxx", server_name: "pg-server-name", target_vm_size: "standard-2", target_storage_size_gib: 100)
      }.to raise_error Validation::ValidationFailed, "Validation failed for following fields: provider"

      expect {
        described_class.assemble(project_id: customer_project.id, location: "hetzner-hel1", server_name: "pg/server/name", target_vm_size: "standard-2", target_storage_size_gib: 100)
      }.to raise_error Validation::ValidationFailed, "Validation failed for following fields: name"

      expect {
        described_class.assemble(project_id: customer_project.id, location: "hetzner-hel1", server_name: "pg-server-name", target_vm_size: "standard-128", target_storage_size_gib: 100)
      }.to raise_error Validation::ValidationFailed, "Validation failed for following fields: size"

      expect {
        described_class.assemble(project_id: customer_project.id, location: "hetzner-hel1", server_name: "pg-server-name", target_vm_size: "standard-2", target_storage_size_gib: 100)
      }.not_to raise_error
    end

    it "passes timeline of parent resource if parent is passed" do
      expect(Config).to receive(:postgres_service_project_id).and_return(postgres_project.id).at_least(:once)

      parent_id = described_class.assemble(project_id: customer_project.id, location: "hetzner-hel1", server_name: "pg-server-name", target_vm_size: "standard-2", target_storage_size_gib: 100).id
      timeline_id = PostgresResource[parent_id].timeline.id
      expect(Prog::Postgres::PostgresServerNexus).to receive(:assemble).with(hash_including(timeline_id: timeline_id, timeline_access: "fetch"))

      described_class.assemble(project_id: customer_project.id, location: "hetzner-hel1", server_name: "pg-server-name-2", target_vm_size: "standard-2", target_storage_size_gib: 100, parent_id: parent_id, restore_target: Time.now)
    end
  end

  describe "#before_run" do
    it "hops to destroy and stops billing records when needed" do
      br = instance_double(BillingRecord)
      expect(br).to receive(:finalize).twice
      expect(postgres_resource).to receive(:active_billing_records).and_return([br, br])
      expect(nx).to receive(:when_destroy_set?).and_yield
      expect { nx.before_run }.to hop("destroy")
    end

    it "does not hop to destroy if already in the destroy state" do
      expect(nx).to receive(:when_destroy_set?).and_yield
      expect(nx.strand).to receive(:label).and_return("destroy")
      expect { nx.before_run }.not_to hop("destroy")
    end
  end

  describe "#start" do
    it "naps if vm not ready" do
      expect(postgres_resource.server.vm).to receive(:strand).and_return(instance_double(Strand, label: "prep"))
      expect { nx.start }.to nap(5)
    end

    it "registers deadline and hops" do
      expect(postgres_resource.server.vm).to receive(:strand).and_return(instance_double(Strand, label: "wait"))
      expect(nx).to receive(:register_deadline)
      expect { nx.start }.to hop("create_dns_record")
    end
  end

  describe "#create_dns_record" do
    it "creates dns records and hops" do
      expect(postgres_resource.server.vm).to receive(:ephemeral_net4).and_return("1.1.1.1")
      expect(postgres_resource).to receive(:hostname).and_return("pg-server-name.postgres.ubicloud.com.")
      dns_zone = instance_double(DnsZone)
      expect(dns_zone).to receive(:insert_record).with(record_name: "pg-server-name.postgres.ubicloud.com.", type: "A", ttl: 10, data: "1.1.1.1")
      expect(nx).to receive(:dns_zone).and_return(dns_zone)
      expect { nx.create_dns_record }.to hop("initialize_certificates")
    end

    it "hops even if dns zone is not configured" do
      expect(nx).to receive(:dns_zone).and_return(nil)
      expect { nx.create_dns_record }.to hop("initialize_certificates")
    end
  end

  describe "#initialize_certificates" do
    it "hops to wait_server after creating certificates" do
      postgres_resource = PostgresResource.create_with_id(
        project_id: "e3e333dd-bd9a-82d2-acc1-1c7c1ee9781f",
        location: "hetzner-hel1",
        server_name: "pg-server-name",
        target_vm_size: "standard-2",
        target_storage_size_gib: 100,
        superuser_password: "dummy-password"
      )

      expect(nx).to receive(:postgres_resource).and_return(postgres_resource).at_least(:once)
      expect(Config).to receive(:postgres_service_hostname).and_return("postgres.ubicloud.com").at_least(:once)

      expect(nx).to receive(:create_root_certificate).with(duration: 60 * 60 * 24 * 365 * 5).and_call_original
      expect(nx).to receive(:create_root_certificate).with(duration: 60 * 60 * 24 * 365 * 10).and_call_original
      expect(nx).to receive(:create_server_certificate).and_call_original

      expect { nx.initialize_certificates }.to hop("wait_server")
    end
  end

  describe "#refresh_certificates" do
    it "rotates root certificate if root_cert_1 is close to expiration" do
      expect(OpenSSL::X509::Certificate).to receive(:new).with("root cert 1").and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 30 * 4))
      expect(OpenSSL::X509::Certificate).to receive(:new).with("server cert").and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 30 * 4))

      expect(nx).to receive(:create_root_certificate).with(hash_including(duration: 60 * 60 * 24 * 365 * 10))
      expect(postgres_resource.server).to receive(:incr_refresh_certificates)

      expect { nx.refresh_certificates }.to hop("wait_server")
    end

    it "rotates server certificate if it is close to expiration" do
      expect(OpenSSL::X509::Certificate).to receive(:new).with("root cert 1").and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 365 * 4))
      expect(OpenSSL::X509::Certificate).to receive(:new).with("server cert").and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 29))

      expect(nx).to receive(:create_server_certificate)
      expect(postgres_resource.server).to receive(:incr_refresh_certificates)

      expect { nx.refresh_certificates }.to hop("wait_server")
    end

    it "rotates server certificate using root_cert_2 if root_cert_1 is close to expiration" do
      root_cert_2 = instance_double(OpenSSL::X509::Certificate)
      expect(OpenSSL::X509::Certificate).to receive(:new).with("root cert 1").twice.and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 360))
      expect(OpenSSL::X509::Certificate).to receive(:new).with("root cert 2").and_return(root_cert_2)
      expect(OpenSSL::X509::Certificate).to receive(:new).with("server cert").and_return(instance_double(OpenSSL::X509::Certificate, not_after: Time.now + 60 * 60 * 24 * 29))

      expect(Util).to receive(:create_certificate).with(hash_including(issuer_cert: root_cert_2)).and_return([instance_double(OpenSSL::X509::Certificate, to_pem: "server cert")])
      expect(postgres_resource.server).to receive(:incr_refresh_certificates)

      expect { nx.refresh_certificates }.to hop("wait_server")
    end
  end

  describe "#wait_server" do
    it "naps if server not ready" do
      expect(postgres_resource.server).to receive(:strand).and_return(instance_double(Strand, label: "start"))
      expect { nx.wait_server }.to nap(5)
    end

    it "hops if server is ready" do
      expect(postgres_resource.server).to receive(:strand).and_return(instance_double(Strand, label: "wait"))
      expect { nx.wait_server }.to hop("create_billing_record")
    end
  end

  describe "#create_billing_record" do
    it "creates billing record for cores and storage then hops" do
      expect(BillingRecord).to receive(:create_with_id).with(
        project_id: postgres_resource.project_id,
        resource_id: postgres_resource.id,
        resource_name: postgres_resource.server_name,
        billing_rate_id: BillingRate.from_resource_properties("PostgresCores", "standard", postgres_resource.location)["id"],
        amount: postgres_resource.server.vm.cores
      )

      expect(BillingRecord).to receive(:create_with_id).with(
        project_id: postgres_resource.project_id,
        resource_id: postgres_resource.id,
        resource_name: postgres_resource.server_name,
        billing_rate_id: BillingRate.from_resource_properties("PostgresStorage", "standard", postgres_resource.location)["id"],
        amount: postgres_resource.target_storage_size_gib
      )

      expect { nx.create_billing_record }.to hop("wait")
    end
  end

  describe "#wait" do
    it "naps" do
      expect(postgres_resource).to receive(:certificate_last_checked_at).and_return(Time.now)
      expect { nx.wait }.to nap(30)
    end

    it "hops to refresh_certificates if the certificate is checked more than 1 months ago" do
      expect(postgres_resource).to receive(:certificate_last_checked_at).and_return(Time.now - 60 * 60 * 24 * 30 - 1)
      expect { nx.wait }.to hop("refresh_certificates")
    end
  end

  describe "#destroy" do
    it "triggers server deletion and waits until it is deleted" do
      dns_zone = instance_double(DnsZone)
      expect(nx).to receive(:dns_zone).and_return(dns_zone)

      expect(postgres_resource.server).to receive(:incr_destroy)
      expect { nx.destroy }.to nap(5)

      expect(postgres_resource).to receive(:server).and_return(nil)
      expect(postgres_resource).to receive(:hostname)
      expect(dns_zone).to receive(:delete_record)
      expect(postgres_resource).to receive(:dissociate_with_project)
      expect(postgres_resource).to receive(:destroy)

      expect { nx.destroy }.to exit({"msg" => "postgres resource is deleted"})
    end

    it "completes destroy even if dns zone is not configured" do
      expect(nx).to receive(:dns_zone).and_return(nil)
      expect(postgres_resource).to receive(:server).and_return(nil)

      expect { nx.destroy }.to exit({"msg" => "postgres resource is deleted"})
    end
  end

  describe "#dns_zone" do
    it "fetches dns zone from database only once" do
      expect(DnsZone).to receive(:where).exactly(:once).and_return([true])

      nx.dns_zone
      nx.dns_zone
    end
  end
end
