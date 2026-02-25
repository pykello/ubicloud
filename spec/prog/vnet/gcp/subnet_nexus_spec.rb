# frozen_string_literal: true

require "google/cloud/compute/v1"
require "google/cloud/resource_manager/v3"

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
  let(:nfp_client) { instance_double(Google::Cloud::Compute::V1::NetworkFirewallPolicies::Rest::Client) }
  let(:tag_keys_client) { instance_double(Google::Cloud::ResourceManager::V3::TagKeys::Rest::Client) }
  let(:tag_values_client) { instance_double(Google::Cloud::ResourceManager::V3::TagValues::Rest::Client) }
  let(:global_ops_client) { instance_double(Google::Cloud::Compute::V1::GlobalOperations::Rest::Client) }
  let(:region_ops_client) { instance_double(Google::Cloud::Compute::V1::RegionOperations::Rest::Client) }

  before do
    nx.instance_variable_set(:@private_subnet, ps)
    allow(credential).to receive_messages(
      networks_client:, subnetworks_client:,
      network_firewall_policies_client: nfp_client,
      tag_keys_client:, tag_values_client:,
      global_operations_client: global_ops_client,
      region_operations_client: region_ops_client
    )
    nx.instance_variable_set(:@credential, credential)
  end

  describe ".vpc_name" do
    it "returns ubicloud-proj-<ubid> for a project" do
      expect(described_class.vpc_name(project)).to eq(vpc_name)
    end
  end

  describe ".tag_key_short_name" do
    it "returns same as vpc_name" do
      expect(described_class.tag_key_short_name(project)).to eq(vpc_name)
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

      expect { nx.create_vpc }.to hop("create_firewall_policy")
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

    it "hops to create_firewall_policy when operation completes" do
      op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).and_return(op)
      expect { nx.wait_create_vpc }.to hop("create_firewall_policy")
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

      expect { nx.wait_create_vpc }.to hop("create_firewall_policy")
    end
  end

  describe "#create_firewall_policy" do
    it "creates firewall policy if not exists and hops to create_tag_key" do
      expect(nfp_client).to receive(:get)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, name: "op-policy")
      expect(nfp_client).to receive(:insert) do |args|
        expect(args[:project]).to eq("test-gcp-project")
        expect(args[:firewall_policy_resource].name).to eq(vpc_name)
        op
      end

      done_op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).with(
        project: "test-gcp-project", operation: "op-policy"
      ).and_return(done_op)

      assoc_op = instance_double(Gapic::GenericLRO::Operation, name: "op-assoc")
      expect(nfp_client).to receive(:add_association) do |args|
        expect(args[:firewall_policy]).to eq(vpc_name)
        assoc = args[:firewall_policy_association_resource]
        expect(assoc.attachment_target).to include(vpc_name)
        assoc_op
      end

      expect(global_ops_client).to receive(:get).with(
        project: "test-gcp-project", operation: "op-assoc"
      ).and_return(done_op)

      expect { nx.create_firewall_policy }.to hop("create_tag_key")
    end

    it "skips creation when firewall policy already exists" do
      expect(nfp_client).to receive(:get).and_return(
        Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name)
      )
      expect(nfp_client).not_to receive(:insert)

      expect { nx.create_firewall_policy }.to hop("create_tag_key")
    end
  end

  describe "#create_tag_key" do
    let(:tag_key) {
      Google::Cloud::ResourceManager::V3::TagKey.new(
        name: "tagKeys/123456",
        short_name: vpc_name
      )
    }
    let(:tag_value) {
      Google::Cloud::ResourceManager::V3::TagValue.new(
        name: "tagValues/789",
        short_name: "vm"
      )
    }

    it "creates tag key and vm tag value when they don't exist" do
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .with(name: "test-gcp-project/#{vpc_name}")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      lro = instance_double(Gapic::Operation, wait_until_done!: nil, error?: false)
      expect(tag_keys_client).to receive(:create_tag_key) do |args|
        expect(args[:tag_key].short_name).to eq(vpc_name)
        expect(args[:tag_key].purpose).to eq(:GCE_FIREWALL)
        expect(args[:tag_key].purpose_data["network"]).to include(vpc_name)
        lro
      end

      # ensure_tag_value("vm") — tag key exists now, value doesn't
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .with(name: "test-gcp-project/#{vpc_name}")
        .and_return(tag_key)
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/vm")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect(tag_values_client).to receive(:create_tag_value) do |args|
        expect(args[:tag_value].parent).to eq("tagKeys/123456")
        expect(args[:tag_value].short_name).to eq("vm")
        lro
      end

      expect { nx.create_tag_key }.to hop("create_vpc_deny_rules")
    end

    it "skips creation when tag key and value already exist" do
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .with(name: "test-gcp-project/#{vpc_name}")
        .and_return(tag_key)

      # ensure_tag_value("vm")
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .with(name: "test-gcp-project/#{vpc_name}")
        .and_return(tag_key)
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/vm")
        .and_return(tag_value)

      expect(tag_keys_client).not_to receive(:create_tag_key)
      expect(tag_values_client).not_to receive(:create_tag_value)

      expect { nx.create_tag_key }.to hop("create_vpc_deny_rules")
    end

    it "raises when tag key creation fails" do
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      error_result = double("error", message: "quota exceeded") # rubocop:disable RSpec/VerifiedDoubles
      lro = instance_double(Gapic::Operation, wait_until_done!: nil, error?: true, error: error_result)
      expect(tag_keys_client).to receive(:create_tag_key).and_return(lro)

      expect { nx.create_tag_key }.to raise_error(RuntimeError, /Tag key creation failed/)
    end
  end

  describe "#create_vpc_deny_rules" do
    let(:vm_tag_value) {
      Google::Cloud::ResourceManager::V3::TagValue.new(name: "tagValues/789", short_name: "vm")
    }

    before do
      allow(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/vm")
        .and_return(vm_tag_value)
    end

    it "creates 4 deny rules when they don't exist" do
      expect(nfp_client).to receive(:get_rule).exactly(4).times
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      created_rules = []
      op = instance_double(Gapic::GenericLRO::Operation, name: "op-rule")
      done_op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).exactly(4).times.and_return(done_op)

      expect(nfp_client).to receive(:add_rule).exactly(4).times do |args|
        rule = args[:firewall_policy_rule_resource]
        created_rules << {
          priority: rule.priority,
          direction: rule.direction,
          action: rule.action,
          target_tags: rule.target_secure_tags.map(&:name)
        }
        op
      end

      expect { nx.create_vpc_deny_rules }.to hop("create_subnet")

      expect(created_rules.map { |r| r[:action] }).to all(eq("deny"))
      expect(created_rules.map { |r| r[:target_tags] }).to all(eq(["tagValues/789"]))
      directions = created_rules.map { |r| r[:direction] }
      expect(directions.count("INGRESS")).to eq(2)
      expect(directions.count("EGRESS")).to eq(2)
    end

    it "skips creation when deny rules already exist" do
      rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new
      expect(nfp_client).to receive(:get_rule).exactly(4).times.and_return(rule)
      expect(nfp_client).not_to receive(:add_rule)

      expect { nx.create_vpc_deny_rules }.to hop("create_subnet")
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
    let(:subnet_tag_value) {
      Google::Cloud::ResourceManager::V3::TagValue.new(
        name: "tagValues/456",
        short_name: "ps-#{ps.ubid}"
      )
    }
    let(:tag_key) {
      Google::Cloud::ResourceManager::V3::TagKey.new(
        name: "tagKeys/123456",
        short_name: vpc_name
      )
    }

    before do
      # ensure_tag_value for subnet tag
      allow(tag_keys_client).to receive(:get_namespaced_tag_key)
        .with(name: "test-gcp-project/#{vpc_name}")
        .and_return(tag_key)
    end

    it "creates subnet tag value and IPv4+IPv6 egress allow rules" do
      # ensure_tag_value — tag value exists
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/ps-#{ps.ubid}")
        .and_return(subnet_tag_value)

      # resolve_tag_value_name
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/ps-#{ps.ubid}")
        .and_return(subnet_tag_value)

      # Two policy rules (IPv4 egress + IPv6 egress), both new
      expect(nfp_client).to receive(:get_rule).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      op = instance_double(Gapic::GenericLRO::Operation, name: "op-rule")
      done_op = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).twice.and_return(done_op)

      created_rules = []
      expect(nfp_client).to receive(:add_rule).twice do |args|
        rule = args[:firewall_policy_rule_resource]
        created_rules << {
          direction: rule.direction,
          action: rule.action,
          target_tags: rule.target_secure_tags.map(&:name)
        }
        op
      end

      expect { nx.create_subnet_allow_rules }.to hop("wait")

      expect(created_rules).to all(include(direction: "EGRESS", action: "allow"))
      expect(created_rules.map { |r| r[:target_tags] }).to all(eq(["tagValues/456"]))
    end

    it "skips creation when rules already exist" do
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/ps-#{ps.ubid}")
        .and_return(subnet_tag_value)
        .at_least(:once)

      rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new
      expect(nfp_client).to receive(:get_rule).twice.and_return(rule)
      expect(nfp_client).not_to receive(:add_rule)

      expect { nx.create_subnet_allow_rules }.to hop("wait")
    end

    it "creates tag value when it doesn't exist" do
      # First call: tag_key exists, tag_value doesn't
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/ps-#{ps.ubid}")
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      lro = instance_double(Gapic::Operation, wait_until_done!: nil, error?: false)
      expect(tag_values_client).to receive(:create_tag_value).and_return(lro)

      # resolve_tag_value_name
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .with(name: "test-gcp-project/#{vpc_name}/ps-#{ps.ubid}")
        .and_return(subnet_tag_value)

      # Rules already exist
      rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new
      expect(nfp_client).to receive(:get_rule).twice.and_return(rule)

      expect { nx.create_subnet_allow_rules }.to hop("wait")
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
    it "destroys the subnet and GCP resources when no nics or load balancers remain" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)

      # delete_subnet_tag_value
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .and_return(Google::Cloud::ResourceManager::V3::TagValue.new(name: "tagValues/456"))
      lro = instance_double(Gapic::Operation, wait_until_done!: nil)
      expect(tag_values_client).to receive(:delete_tag_value).and_return(lro)

      # delete_subnet_policy_rules
      expect(nfp_client).to receive(:remove_rule).twice

      # delete_gcp_subnet
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

      # delete_subnet_tag_value — already deleted
      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      # delete_subnet_policy_rules — already deleted
      expect(nfp_client).to receive(:remove_rule).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect(subnetworks_client).to receive(:delete).and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(nx).to receive(:maybe_delete_vpc)
      expect(ps).to receive(:destroy)
      expect { nx.destroy }.to exit({"msg" => "subnet destroyed"})
    end

    it "naps when GCE subnet is still in use by a terminating instance" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)

      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(nfp_client).to receive(:remove_rule).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect(subnetworks_client).to receive(:delete).and_raise(
        Google::Cloud::InvalidArgumentError.new("The subnetwork resource is already being used by 'projects/test/instances/vm-1'")
      )
      expect { nx.destroy }.to nap(5)
    end

    it "re-raises InvalidArgumentError when not about subnet being used" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)

      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(nfp_client).to receive(:remove_rule).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

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

    it "handles policy not found during rule cleanup" do
      expect(ps).to receive(:nics).and_return([]).at_least(:once)
      expect(ps).to receive(:load_balancers).and_return([]).at_least(:once)
      expect(ps).to receive(:remove_all_firewalls)

      expect(tag_values_client).to receive(:get_namespaced_tag_value)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      # Both priority rules not found (inner rescue catches each one)
      expect(nfp_client).to receive(:remove_rule).twice
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect(subnetworks_client).to receive(:delete)
      expect(nx).to receive(:maybe_delete_vpc)
      expect(ps).to receive(:destroy)
      expect { nx.destroy }.to exit({"msg" => "subnet destroyed"})
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

    it "deletes firewall policy, tag key, and VPC when no other GCP subnets remain" do
      allow(ps_dataset).to receive(:count).and_return(0)

      # delete_firewall_policy
      expect(nfp_client).to receive(:delete)
        .with(project: "test-gcp-project", firewall_policy: vpc_name)

      # delete_tag_key
      tag_key = Google::Cloud::ResourceManager::V3::TagKey.new(name: "tagKeys/123")
      expect(tag_keys_client).to receive(:get_namespaced_tag_key).and_return(tag_key)
      vm_tv = Google::Cloud::ResourceManager::V3::TagValue.new(name: "tagValues/789")
      expect(tag_values_client).to receive(:list_tag_values).and_return([vm_tv])
      lro = instance_double(Gapic::Operation, wait_until_done!: nil)
      expect(tag_values_client).to receive(:delete_tag_value).with(name: "tagValues/789").and_return(lro)
      expect(tag_keys_client).to receive(:delete_tag_key).with(name: "tagKeys/123").and_return(lro)

      # delete_vpc_network
      expect(networks_client).to receive(:delete)
        .with(project: "test-gcp-project", network: vpc_name)

      nx.send(:maybe_delete_vpc)
    end

    it "does not delete VPC when other GCP subnets remain in project" do
      allow(ps_dataset).to receive(:count).and_return(1)

      expect(nfp_client).not_to receive(:delete)
      expect(tag_keys_client).not_to receive(:delete_tag_key)
      expect(networks_client).not_to receive(:delete)

      nx.send(:maybe_delete_vpc)
    end

    it "handles already-deleted resources gracefully" do
      allow(ps_dataset).to receive(:count).and_return(0)

      expect(nfp_client).to receive(:delete)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(tag_keys_client).to receive(:get_namespaced_tag_key)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))
      expect(networks_client).to receive(:delete)
        .and_raise(Google::Cloud::NotFoundError.new("not found"))

      nx.send(:maybe_delete_vpc)
    end
  end

  describe "#wait_for_compute_global_op" do
    it "polls until done" do
      op = instance_double(Gapic::GenericLRO::Operation, name: "op-test")
      done = Google::Cloud::Compute::V1::Operation.new(status: :DONE)
      expect(global_ops_client).to receive(:get).and_return(done)

      nx.send(:wait_for_compute_global_op, op)
    end

    it "polls multiple times if not done" do
      op = instance_double(Gapic::GenericLRO::Operation, name: "op-test")
      running = Google::Cloud::Compute::V1::Operation.new(status: :RUNNING)
      done = Google::Cloud::Compute::V1::Operation.new(status: :DONE)

      expect(global_ops_client).to receive(:get).and_return(running, done)
      allow(nx).to receive(:sleep)

      nx.send(:wait_for_compute_global_op, op)
    end

    it "handles non-operation objects" do
      op = double("plain_op") # rubocop:disable RSpec/VerifiedDoubles
      expect { nx.send(:wait_for_compute_global_op, op) }.not_to raise_error
    end
  end
end
