# frozen_string_literal: true

require "google/cloud/compute/v1"

RSpec.describe Prog::Vnet::Gcp::SubnetNexus do
  subject(:nx) { described_class.new(st) }

  let(:st) { Strand.create(prog: "Vnet::Gcp::SubnetNexus", label: "start") }
  let(:project) { Project.create(name: "test-gcp-subnet") }
  let(:location) {
    Location.create(name: "gcp-us-central1", provider: "gcp", project_id: project.id,
      display_name: "GCP US Central 1", ui_name: "GCP US Central 1", visible: true)
  }
  let(:credential) {
    LocationCredential.create_with_id(location,
      project_id: "test-gcp-project",
      service_account_email: "test@test-gcp-project.iam.gserviceaccount.com",
      credentials_json: "{}")
  }
  let(:ps) {
    credential
    PrivateSubnet.create(name: "ps", location_id: location.id, net6: "fd10:9b0b:6b4b:8fbb::/64",
      net4: "10.0.0.0/26", state: "waiting", project_id: project.id)
  }
  let(:vpc_name) { "ubicloud-proj-#{project.ubid}" }
  let(:networks_client) { instance_double(Google::Cloud::Compute::V1::Networks::Rest::Client) }
  let(:subnetworks_client) { instance_double(Google::Cloud::Compute::V1::Subnetworks::Rest::Client) }
  let(:firewalls_client) { instance_double(Google::Cloud::Compute::V1::Firewalls::Rest::Client) }
  let(:global_ops_client) { instance_double(Google::Cloud::Compute::V1::GlobalOperations::Rest::Client) }
  let(:region_ops_client) { instance_double(Google::Cloud::Compute::V1::RegionOperations::Rest::Client) }

  before do
    nx.instance_variable_set(:@private_subnet, ps)
    allow_any_instance_of(LocationCredential).to receive(:networks_client).and_return(networks_client)
    allow_any_instance_of(LocationCredential).to receive(:subnetworks_client).and_return(subnetworks_client)
    allow_any_instance_of(LocationCredential).to receive(:firewalls_client).and_return(firewalls_client)
    allow_any_instance_of(LocationCredential).to receive(:global_operations_client).and_return(global_ops_client)
    allow_any_instance_of(LocationCredential).to receive(:region_operations_client).and_return(region_ops_client)
  end

  describe ".vpc_name" do
    it "returns ubicloud-proj-<ubid> for a project" do
      expect(described_class.vpc_name(project)).to eq(vpc_name)
    end
  end

  describe "#start" do
    it "hops to create_vpc" do
      expect { nx.start }.to hop("create_vpc")
    end
  end

  describe "#create_vpc" do
    it "skips creation if VPC already exists" do
      expect(networks_client).to receive(:get).with(
        project: "test-gcp-project",
        network: vpc_name
      ).and_return(Google::Cloud::Compute::V1::Network.new(name: vpc_name))

      expect { nx.create_vpc }.to hop("create_vpc_firewall_rules")
    end

    it "creates VPC and hops to wait_create_vpc" do
      expect(networks_client).to receive(:get).and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, name: "op-vpc-123")
      expect(networks_client).to receive(:insert) do |args|
        expect(args[:project]).to eq("test-gcp-project")
        nr = args[:network_resource]
        expect(nr.name).to eq(vpc_name)
        expect(nr.auto_create_subnetworks).to be(false)
        op
      end

      expect { nx.create_vpc }.to hop("wait_create_vpc")
      expect(st.stack.first["gcp_op_name"]).to eq("op-vpc-123")
    end
  end

  describe "#wait_create_vpc" do
    before do
      st.stack.first["gcp_op_name"] = "op-vpc-123"
      st.stack.first["gcp_op_scope"] = "global"
      st.modified!(:stack)
      st.save_changes
      nx.instance_variable_set(:@frame, nil)
    end

    it "naps when operation is still running" do
      op = Google::Cloud::Compute::V1::Operation.new(status: :RUNNING)
      expect(global_ops_client).to receive(:get).and_return(op)
      expect { nx.wait_create_vpc }.to nap(5)
    end

    it "hops to create_vpc_firewall_rules when operation completes" do
      op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).and_return(op)
      expect { nx.wait_create_vpc }.to hop("create_vpc_firewall_rules")
    end

    it "raises if VPC creation fails" do
      error_entry = Google::Cloud::Compute::V1::Errors.new(code: "ERROR", message: "operation failed")
      op = Google::Cloud::Compute::V1::Operation.new(
        status: :DONE,
        error: Google::Cloud::Compute::V1::Error.new(errors: [error_entry])
      )
      expect(global_ops_client).to receive(:get).and_return(op)
      expect(networks_client).to receive(:get)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect { nx.wait_create_vpc }.to raise_error(RuntimeError, /VPC.*creation failed/)
    end

    it "continues if LRO errors but VPC was created" do
      error_entry = Google::Cloud::Compute::V1::Errors.new(code: "TRANSIENT", message: "transient error")
      op = Google::Cloud::Compute::V1::Operation.new(
        status: :DONE,
        error: Google::Cloud::Compute::V1::Error.new(errors: [error_entry])
      )
      expect(global_ops_client).to receive(:get).and_return(op)
      expect(networks_client).to receive(:get)
        .and_return(Google::Cloud::Compute::V1::Network.new(name: vpc_name))

      expect { nx.wait_create_vpc }.to hop("create_vpc_firewall_rules")
    end
  end

  describe "#create_vpc_firewall_rules" do
    it "creates all deny rules (IPv4 and IPv6) when they do not exist" do
      %w[deny-ingress deny-egress deny-ingress-ipv6 deny-egress-ipv6].each do |suffix|
        expect(firewalls_client).to receive(:get)
          .with(project: "test-gcp-project", firewall: "#{vpc_name}-#{suffix}")
          .and_raise(Google::Cloud::NotFoundError.new("not found"))
      end

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      # verify_lro checks error? without blocking.exactly(4).times

      created_rules = []
      expect(firewalls_client).to receive(:insert).exactly(4).times do |args|
        fw = args[:firewall_resource]
        created_rules << {
          name: fw.name,
          direction: fw.direction,
          priority: fw.priority,
          target_tags: fw.target_tags.to_a,
          denied: fw.denied.map(&:I_p_protocol)
        }
        op
      end

      expect { nx.create_vpc_firewall_rules }.to hop("create_subnet")

      ingress_rule = created_rules.find { |r| r[:name] == "#{vpc_name}-deny-ingress" }
      expect(ingress_rule[:direction]).to eq("INGRESS")
      expect(ingress_rule[:priority]).to eq(65534)
      expect(ingress_rule[:target_tags]).to eq(["ubicloud-vm"])
      expect(ingress_rule[:denied]).to eq(["all"])

      egress_rule = created_rules.find { |r| r[:name] == "#{vpc_name}-deny-egress" }
      expect(egress_rule[:direction]).to eq("EGRESS")
      expect(egress_rule[:priority]).to eq(65534)
      expect(egress_rule[:target_tags]).to eq(["ubicloud-vm"])
      expect(egress_rule[:denied]).to eq(["all"])

      ingress_ipv6_rule = created_rules.find { |r| r[:name] == "#{vpc_name}-deny-ingress-ipv6" }
      expect(ingress_ipv6_rule[:direction]).to eq("INGRESS")
      expect(ingress_ipv6_rule[:priority]).to eq(65534)

      egress_ipv6_rule = created_rules.find { |r| r[:name] == "#{vpc_name}-deny-egress-ipv6" }
      expect(egress_ipv6_rule[:direction]).to eq("EGRESS")
      expect(egress_ipv6_rule[:priority]).to eq(65534)
    end

    it "skips creation when deny rules already exist" do
      %w[deny-ingress deny-egress deny-ingress-ipv6 deny-egress-ipv6].each do |suffix|
        expect(firewalls_client).to receive(:get)
          .with(project: "test-gcp-project", firewall: "#{vpc_name}-#{suffix}")
          .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-#{suffix}"))
      end

      expect(firewalls_client).not_to receive(:insert)

      expect { nx.create_vpc_firewall_rules }.to hop("create_subnet")
    end

    it "raises if deny rule creation fails" do
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-ingress")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
        .twice

      op = instance_double(Gapic::GenericLRO::Operation, error?: true, error: "operation failed")
      # verify_lro checks error? without blocking
      expect(firewalls_client).to receive(:insert).and_return(op)

      expect { nx.create_vpc_firewall_rules }.to raise_error(RuntimeError, /firewall rule.*creation failed/)
    end

    it "sets correct source_ranges for IPv4 ingress deny rule" do
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-ingress")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      # Other rules already exist
      %w[deny-egress deny-ingress-ipv6 deny-egress-ipv6].each do |suffix|
        expect(firewalls_client).to receive(:get)
          .with(project: "test-gcp-project", firewall: "#{vpc_name}-#{suffix}")
          .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-#{suffix}"))
      end

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      # verify_lro checks error? without blocking

      expect(firewalls_client).to receive(:insert) do |args|
        fw = args[:firewall_resource]
        expect(fw.source_ranges.to_a).to eq(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        expect(fw.destination_ranges.to_a).to be_empty
        op
      end

      expect { nx.create_vpc_firewall_rules }.to hop("create_subnet")
    end

    it "sets correct destination_ranges for IPv4 egress deny rule" do
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-ingress")
        .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-deny-ingress"))
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-egress")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      # IPv6 rules already exist
      %w[deny-ingress-ipv6 deny-egress-ipv6].each do |suffix|
        expect(firewalls_client).to receive(:get)
          .with(project: "test-gcp-project", firewall: "#{vpc_name}-#{suffix}")
          .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-#{suffix}"))
      end

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      # verify_lro checks error? without blocking

      expect(firewalls_client).to receive(:insert) do |args|
        fw = args[:firewall_resource]
        expect(fw.destination_ranges.to_a).to eq(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        expect(fw.source_ranges.to_a).to be_empty
        op
      end

      expect { nx.create_vpc_firewall_rules }.to hop("create_subnet")
    end

    it "sets correct source_ranges for IPv6 ingress deny rule" do
      # IPv4 rules already exist
      %w[deny-ingress deny-egress].each do |suffix|
        expect(firewalls_client).to receive(:get)
          .with(project: "test-gcp-project", firewall: "#{vpc_name}-#{suffix}")
          .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-#{suffix}"))
      end
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-ingress-ipv6")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(firewalls_client).to receive(:get)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-egress-ipv6")
        .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-deny-egress-ipv6"))

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      # verify_lro checks error? without blocking

      expect(firewalls_client).to receive(:insert) do |args|
        fw = args[:firewall_resource]
        expect(fw.source_ranges.to_a).to eq(["fd20::/20"])
        expect(fw.destination_ranges.to_a).to be_empty
        op
      end

      expect { nx.create_vpc_firewall_rules }.to hop("create_subnet")
    end
  end

  describe "#create_subnet" do
    it "skips creation if subnet already exists" do
      expect(subnetworks_client).to receive(:get).with(
        project: "test-gcp-project",
        region: "us-central1",
        subnetwork: "ubicloud-#{ps.ubid}"
      ).and_return(Google::Cloud::Compute::V1::Subnetwork.new)

      expect { nx.create_subnet }.to hop("create_subnet_allow_rules")
    end

    it "creates dual-stack subnet and hops to wait_create_subnet" do
      expect(subnetworks_client).to receive(:get).and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, name: "op-subnet-123")
      expect(subnetworks_client).to receive(:insert) do |args|
        expect(args[:project]).to eq("test-gcp-project")
        expect(args[:region]).to eq("us-central1")
        sr = args[:subnetwork_resource]
        expect(sr.name).to eq("ubicloud-#{ps.ubid}")
        expect(sr.ip_cidr_range).to eq("10.0.0.0/26")
        expect(sr.network).to eq("projects/test-gcp-project/global/networks/#{vpc_name}")
        expect(sr.private_ip_google_access).to be(true)
        expect(sr.stack_type).to eq("IPV4_IPV6")
        expect(sr.ipv6_access_type).to eq("EXTERNAL")
        op
      end

      expect { nx.create_subnet }.to hop("wait_create_subnet")
      expect(st.stack.first["gcp_op_name"]).to eq("op-subnet-123")
    end
  end

  describe "#wait_create_subnet" do
    before do
      st.stack.first["gcp_op_name"] = "op-subnet-123"
      st.stack.first["gcp_op_scope"] = "region"
      st.stack.first["gcp_op_scope_value"] = "us-central1"
      st.modified!(:stack)
      st.save_changes
      nx.instance_variable_set(:@frame, nil)
    end

    it "naps when operation is still running" do
      op = Google::Cloud::Compute::V1::Operation.new(status: :RUNNING)
      expect(region_ops_client).to receive(:get).and_return(op)
      expect { nx.wait_create_subnet }.to nap(5)
    end

    it "hops to create_subnet_allow_rules when operation completes" do
      op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(region_ops_client).to receive(:get).and_return(op)
      expect { nx.wait_create_subnet }.to hop("create_subnet_allow_rules")
    end

    it "raises if subnet creation fails" do
      error_entry = Google::Cloud::Compute::V1::Errors.new(code: "ERROR", message: "operation failed")
      op = Google::Cloud::Compute::V1::Operation.new(
        status: :DONE,
        error: Google::Cloud::Compute::V1::Error.new(errors: [error_entry])
      )
      expect(region_ops_client).to receive(:get).and_return(op)
      expect(subnetworks_client).to receive(:get)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect { nx.wait_create_subnet }.to raise_error(RuntimeError, /subnet.*creation failed/)
    end

    it "continues if LRO errors but subnet was created" do
      error_entry = Google::Cloud::Compute::V1::Errors.new(code: "TRANSIENT", message: "transient error")
      op = Google::Cloud::Compute::V1::Operation.new(
        status: :DONE,
        error: Google::Cloud::Compute::V1::Error.new(errors: [error_entry])
      )
      expect(region_ops_client).to receive(:get).and_return(op)
      expect(subnetworks_client).to receive(:get)
        .and_return(Google::Cloud::Compute::V1::Subnetwork.new(name: "ubicloud-#{ps.ubid}"))

      expect { nx.wait_create_subnet }.to hop("create_subnet_allow_rules")
    end
  end

  describe "#create_subnet_allow_rules" do
    it "creates IPv4 and IPv6 egress allow rules for the subnet" do
      # Both rules already exist
      expect(firewalls_client).to receive(:get).twice
        .and_return(Google::Cloud::Compute::V1::Firewall.new)
      expect(firewalls_client).not_to receive(:insert)

      expect { nx.create_subnet_allow_rules }.to hop("wait")
    end

    it "creates IPv4 and IPv6 allow rules when they don't exist" do
      expect(firewalls_client).to receive(:get).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      created_rules = []
      expect(firewalls_client).to receive(:insert).twice do |args|
        fw = args[:firewall_resource]
        created_rules << {name: fw.name, direction: fw.direction, priority: fw.priority,
                          target_tags: fw.target_tags.to_a}
        op
      end

      expect { nx.create_subnet_allow_rules }.to hop("wait")

      created_rules.each do |r|
        expect(r[:direction]).to eq("EGRESS")
        expect(r[:priority]).to eq(1000)
        expect(r[:target_tags]).to eq(["ps-#{ps.ubid}"])
      end
    end
  end

  describe "#wait" do
    it "naps" do
      expect { nx.wait }.to nap(10 * 60)
    end

    it "clears refresh_keys semaphore when set" do
      st_real = Strand.create_with_id(ps, prog: "Vnet::Gcp::SubnetNexus", label: "wait")
      real_nx = described_class.new(st_real)
      real_nx.incr_refresh_keys
      expect { real_nx.wait }.to nap(10 * 60)
      expect(Semaphore.where(strand_id: st_real.id, name: "refresh_keys").count).to eq(0)
    end

    it "propagates firewall updates to VMs" do
      st_real = Strand.create_with_id(ps, prog: "Vnet::Gcp::SubnetNexus", label: "wait")
      real_nx = described_class.new(st_real)
      real_nx.incr_update_firewall_rules
      vm = instance_double(Vm)
      expect(real_nx).to receive(:private_subnet).and_return(ps).at_least(:once)
      expect(ps).to receive(:vms).and_return([vm])
      expect(vm).to receive(:incr_update_firewall_rules)
      expect { real_nx.wait }.to nap(10 * 60)
    end
  end

  describe "#destroy" do
    it "destroys the subnet and GCP subnet when no nics or load balancers remain" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)
      expect(subnetworks_client).to receive(:delete).with(
        project: "test-gcp-project",
        region: "us-central1",
        subnetwork: "ubicloud-#{ps.ubid}"
      )
      expect(nx).to receive(:maybe_delete_vpc)
      expect(ps).to receive(:destroy)
      expect { nx.destroy }.to exit({"msg" => "subnet destroyed"})
    end

    it "handles already-deleted GCP subnet" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)
      expect(subnetworks_client).to receive(:delete).and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(nx).to receive(:maybe_delete_vpc)
      expect(ps).to receive(:destroy)
      expect { nx.destroy }.to exit({"msg" => "subnet destroyed"})
    end

    it "naps when GCE subnet is still in use by a terminating instance" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)
      expect(subnetworks_client).to receive(:delete).and_raise(
        Google::Cloud::InvalidArgumentError.new("The subnetwork resource is already being used by 'projects/test/instances/vm-1'")
      )
      expect { nx.destroy }.to nap(5)
    end

    it "re-raises InvalidArgumentError when not about subnet being used" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)
      expect(subnetworks_client).to receive(:delete).and_raise(
        Google::Cloud::InvalidArgumentError.new("Invalid CIDR range")
      )
      expect { nx.destroy }.to raise_error(Google::Cloud::InvalidArgumentError)
    end

    it "destroys nics and load balancers first" do
      nic = instance_double(Nic)
      lb = instance_double(LoadBalancer)
      expect(ps).to receive(:nics).and_return([nic]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([lb]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)
      expect(nic).to receive(:incr_destroy)
      expect(lb).to receive(:incr_destroy)
      expect(nx).to receive(:rand).with(5..10).and_return(7)
      expect { nx.destroy }.to nap(7)
    end
  end

  describe "#maybe_delete_vpc" do
    let(:ps_dataset) {
      dataset = instance_double(Sequel::Dataset)
      allow(project).to receive(:private_subnets_dataset).and_return(dataset)
      allow(dataset).to receive_messages(where: dataset)
      dataset
    }

    before do
      allow(ps).to receive(:project).and_return(project)
    end

    it "deletes VPC and firewall rules when no other GCP subnets remain in project" do
      allow(ps_dataset).to receive(:count).and_return(0)

      deny_ingress = Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-deny-ingress")
      deny_egress = Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-deny-egress")
      expect(firewalls_client).to receive(:list).and_return([deny_ingress, deny_egress])

      expect(firewalls_client).to receive(:delete)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-ingress")
      expect(firewalls_client).to receive(:delete)
        .with(project: "test-gcp-project", firewall: "#{vpc_name}-deny-egress")

      expect(networks_client).to receive(:delete)
        .with(project: "test-gcp-project", network: vpc_name)

      nx.send(:maybe_delete_vpc)
    end

    it "does not delete VPC when other GCP subnets remain in project" do
      allow(ps_dataset).to receive(:count).and_return(1)

      expect(firewalls_client).not_to receive(:list)
      expect(firewalls_client).not_to receive(:delete)
      expect(networks_client).not_to receive(:delete)

      nx.send(:maybe_delete_vpc)
    end

    it "handles already-deleted VPC gracefully" do
      allow(ps_dataset).to receive(:count).and_return(0)

      expect(firewalls_client).to receive(:list)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(networks_client).to receive(:delete)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      nx.send(:maybe_delete_vpc)
    end

    it "handles already-deleted firewall rules during list iteration" do
      allow(ps_dataset).to receive(:count).and_return(0)

      rule = Google::Cloud::Compute::V1::Firewall.new(name: "#{vpc_name}-deny-ingress")
      expect(firewalls_client).to receive(:list).and_return([rule])
      expect(firewalls_client).to receive(:delete)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect(networks_client).to receive(:delete)
        .with(project: "test-gcp-project", network: vpc_name)

      nx.send(:maybe_delete_vpc)
    end
  end

  describe "#verify_lro" do
    it "does nothing when operation has no error? method" do
      op = double("op") # rubocop:disable RSpec/VerifiedDoubles
      expect { nx.send(:verify_lro, op, "test resource") {} }.not_to raise_error
    end

    it "does nothing when operation has no error" do
      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      expect { nx.send(:verify_lro, op, "test resource") {} }.not_to raise_error
    end

    it "recovers when operation has error but resource exists" do
      op = instance_double(Gapic::GenericLRO::Operation, error?: true, error: "error msg")
      expect(Clog).to receive(:emit)
      nx.send(:verify_lro, op, "test resource") { "resource exists" }
    end

    it "raises when operation has error and resource does not exist" do
      op = instance_double(Gapic::GenericLRO::Operation, error?: true, error: "error msg")
      expect {
        nx.send(:verify_lro, op, "test resource") { raise Google::Cloud::NotFoundError.new("not found") }
      }.to raise_error(RuntimeError, /GCP test resource creation failed/)
    end
  end

  describe "#ensure_allow_rule" do
    it "sets source_ranges when provided" do
      expect(firewalls_client).to receive(:get)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, error?: false)
      expect(firewalls_client).to receive(:insert) do |args|
        fw = args[:firewall_resource]
        expect(fw.source_ranges.to_a).to eq(["10.0.0.0/26"])
        expect(fw.destination_ranges.to_a).to be_empty
        op
      end

      nx.send(:ensure_allow_rule,
        name: "test-ingress-rule",
        direction: "INGRESS",
        source_ranges: ["10.0.0.0/26"],
        destination_ranges: nil,
        allowed: [Google::Cloud::Compute::V1::Allowed.new(I_p_protocol: "all")])
    end

    it "invokes recovery block when LRO has error" do
      expect(firewalls_client).to receive(:get)
        .with(hash_including(firewall: "test-allow-rule"))
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, error?: true, error: "transient error")
      expect(firewalls_client).to receive(:insert).and_return(op)

      # verify_lro will call the recovery block which calls firewalls_client.get again
      expect(firewalls_client).to receive(:get)
        .with(hash_including(firewall: "test-allow-rule"))
        .and_return(Google::Cloud::Compute::V1::Firewall.new(name: "test-allow-rule"))
      expect(Clog).to receive(:emit)

      nx.send(:ensure_allow_rule,
        name: "test-allow-rule",
        direction: "EGRESS",
        source_ranges: nil,
        destination_ranges: ["10.0.0.0/26"],
        allowed: [Google::Cloud::Compute::V1::Allowed.new(I_p_protocol: "all")])
    end
  end

  # rubocop:disable RSpec/VerifiedDoubles
  describe "#lro_error_message" do
    it "returns string representation when error has no code method" do
      op = double("op", error: "simple error")
      expect(nx.send(:lro_error_message, op)).to eq("simple error")
    end

    it "returns formatted message with code when error has code" do
      error = double("error", code: 500, message: "Internal error")
      op = double("op", error:)
      expect(nx.send(:lro_error_message, op)).to eq("Internal error (code: 500)")
    end
  end
  # rubocop:enable RSpec/VerifiedDoubles
end
