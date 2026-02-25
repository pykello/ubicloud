# frozen_string_literal: true

require "google/cloud/compute/v1"

RSpec.describe Prog::Vnet::Gcp::UpdateFirewallRules do
  subject(:nx) { described_class.new(st) }

  let(:st) { Strand.new }
  let(:vm) { instance_double(Vm, name: "testvm") }
  let(:location) { instance_double(Location, name: "us-central1", location_credential: credential) }
  let(:vpc_name) { "ubicloud-us-central1" }
  let(:nfp_client) { instance_double(Google::Cloud::Compute::V1::NetworkFirewallPolicies::Rest::Client) }
  let(:credential) {
    instance_double(LocationCredential,
      network_firewall_policies_client: nfp_client,
      project_id: "test-gcp-project")
  }
  let(:vm_dest_ip_range) { "10.0.0.1/32" }

  before do
    nx.instance_variable_set(:@vm, vm)
    nic = instance_double(Nic)
    private_ipv4 = instance_double(NetAddr::IPv4Net)
    network = instance_double(NetAddr::IPv4, to_s: "10.0.0.1")
    allow(private_ipv4).to receive(:network).and_return(network)
    allow(nic).to receive(:private_ipv4).and_return(private_ipv4)
    allow(vm).to receive_messages(location:, nics: [nic])
  end

  describe "#before_run" do
    it "pops if vm is to be destroyed" do
      expect(vm).to receive(:destroy_set?).and_return(true)
      expect { nx.before_run }.to exit({"msg" => "firewall rule is added"})
    end

    it "does not pop if vm is not to be destroyed" do
      expect(vm).to receive(:destroy_set?).and_return(false)
      expect { nx.before_run }.not_to exit
    end
  end

  describe "#update_firewall_rules" do
    let(:empty_policy) {
      Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [])
    }

    it "pops when there are no firewall rules" do
      expect(vm).to receive(:firewall_rules).and_return([])
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "creates a policy rule for IPv4 rules" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule) do |args|
        expect(args[:project]).to eq("test-gcp-project")
        expect(args[:firewall_policy]).to eq(vpc_name)
        rule = args[:firewall_policy_rule_resource]
        expect(rule.direction).to eq("INGRESS")
        expect(rule.action).to eq("allow")
        expect(rule.match.src_ip_ranges).to eq(["0.0.0.0/0"])
        expect(rule.match.dest_ip_ranges).to eq([vm_dest_ip_range])
        expect(rule.match.layer4_configs.size).to eq(1)
        expect(rule.match.layer4_configs.first.ip_protocol).to eq("tcp")
        expect(rule.match.layer4_configs.first.ports).to eq(["5432"])
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "creates separate policy rules for different CIDRs" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp"),
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("10.0.0.0/24"),
          port_range: Sequel.pg_range(22..23), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      created_priorities = []
      expect(nfp_client).to receive(:add_rule).twice do |args|
        created_priorities << args[:firewall_policy_rule_resource].priority
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
      expect(created_priorities.uniq.size).to eq(2)
    end

    it "creates a policy rule for IPv6 rules" do
      rules = [
        instance_double(FirewallRule, ip6?: true, cidr: NetAddr::IPv6Net.parse("::/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule) do |args|
        rule = args[:firewall_policy_rule_resource]
        expect(rule.match.src_ip_ranges).to eq(["::/0"])
        expect(rule.match.dest_ip_ranges).to eq([vm_dest_ip_range])
        expect(rule.match.layer4_configs.first.ip_protocol).to eq("tcp")
        expect(rule.match.layer4_configs.first.ports).to eq(["5432"])
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "creates separate rules for IPv4 and IPv6" do
      rules = [
        instance_double(FirewallRule, ip6?: true, cidr: NetAddr::IPv6Net.parse("::/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp"),
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      created_cidrs = []
      expect(nfp_client).to receive(:add_rule).twice do |args|
        rule = args[:firewall_policy_rule_resource]
        created_cidrs << rule.match.src_ip_ranges.to_a
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
      expect(created_cidrs.flatten).to contain_exactly("0.0.0.0/0", "::/0")
    end

    it "updates an existing policy rule when it doesn't match" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)

      base_priority = described_class::VM_RULE_BASE_PRIORITY + ("testvm".hash.abs % described_class::VM_RULE_PRIORITY_RANGE)
      existing_rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
        priority: base_priority,
        direction: "INGRESS",
        action: "allow",
        match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(
          src_ip_ranges: ["10.0.0.0/8"],
          dest_ip_ranges: [vm_dest_ip_range],
          layer4_configs: [Google::Cloud::Compute::V1::FirewallPolicyRuleMatcherLayer4Config.new(ip_protocol: "tcp", ports: ["22"])]
        )
      )
      policy = Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [existing_rule])
      expect(nfp_client).to receive(:get).and_return(policy)

      expect(nfp_client).to receive(:patch_rule).with(
        hash_including(project: "test-gcp-project", firewall_policy: vpc_name, priority: base_priority)
      )

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "deletes stale policy rules" do
      expect(vm).to receive(:firewall_rules).and_return([])

      stale_rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
        priority: 12345,
        direction: "INGRESS",
        action: "allow",
        match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(
          dest_ip_ranges: [vm_dest_ip_range]
        )
      )
      policy = Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [stale_rule])
      expect(nfp_client).to receive(:get).and_return(policy)

      expect(nfp_client).to receive(:remove_rule).with(
        project: "test-gcp-project",
        firewall_policy: vpc_name,
        priority: 12345
      )

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "handles NotFoundError when deleting stale rules" do
      expect(vm).to receive(:firewall_rules).and_return([])

      stale_rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
        priority: 12345,
        direction: "INGRESS",
        action: "allow",
        match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(
          dest_ip_ranges: [vm_dest_ip_range]
        )
      )
      policy = Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [stale_rule])
      expect(nfp_client).to receive(:get).and_return(policy)

      expect(nfp_client).to receive(:remove_rule).and_raise(Google::Cloud::NotFoundError.new("not found"))

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "handles list errors gracefully" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_raise(Google::Cloud::Error.new("list failed"))

      expect(nfp_client).to receive(:add_rule)

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "handles port ranges correctly" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(80..10000), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule) do |args|
        rule = args[:firewall_policy_rule_resource]
        expect(rule.match.layer4_configs.first.ports).to eq(["80-9999"])
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "groups multiple ports from the same CIDR into one rule" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp"),
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(22..23), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule) do |args|
        rule = args[:firewall_policy_rule_resource]
        expect(rule.match.layer4_configs.size).to eq(1)
        expect(rule.match.layer4_configs.first.ports).to contain_exactly("5432", "22")
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "groups UDP and TCP separately" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp"),
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(53..54), protocol: "udp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule) do |args|
        rule = args[:firewall_policy_rule_resource]
        expect(rule.match.layer4_configs.size).to eq(2)
        protocols = rule.match.layer4_configs.map(&:ip_protocol)
        expect(protocols).to contain_exactly("tcp", "udp")
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "skips rules without port_range" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: nil),
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule).once

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "falls back to update when insert raises AlreadyExistsError" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(empty_policy)

      expect(nfp_client).to receive(:add_rule).and_raise(Google::Cloud::AlreadyExistsError.new("exists"))
      expect(nfp_client).to receive(:patch_rule)

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "skips update when existing rule matches desired state" do
      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(5432..5433), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)

      base_priority = described_class::VM_RULE_BASE_PRIORITY + ("testvm".hash.abs % described_class::VM_RULE_PRIORITY_RANGE)
      existing_rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
        priority: base_priority,
        direction: "INGRESS",
        action: "allow",
        match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(
          src_ip_ranges: ["0.0.0.0/0"],
          dest_ip_ranges: [vm_dest_ip_range],
          layer4_configs: [
            Google::Cloud::Compute::V1::FirewallPolicyRuleMatcherLayer4Config.new(
              ip_protocol: "tcp",
              ports: ["5432"]
            )
          ]
        )
      )
      policy = Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [existing_rule])
      expect(nfp_client).to receive(:get).and_return(policy)

      expect(nfp_client).not_to receive(:patch_rule)
      expect(nfp_client).not_to receive(:add_rule)

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "resolves vpc name from vm location" do
      nx.instance_variable_set(:@firewall_policy_name, nil)

      rules = [
        instance_double(FirewallRule, ip6?: false, cidr: NetAddr::IPv4Net.parse("0.0.0.0/0"),
          port_range: Sequel.pg_range(22..23), protocol: "tcp")
      ]
      expect(vm).to receive(:firewall_rules).and_return(rules)
      expect(nfp_client).to receive(:get).and_return(
        Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [])
      )

      expect(nfp_client).to receive(:add_rule) do |args|
        expect(args[:firewall_policy]).to eq("ubicloud-us-central1")
      end

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end

    it "ignores rules targeting other VMs in the same policy" do
      expect(vm).to receive(:firewall_rules).and_return([])

      other_vm_rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
        priority: 50000,
        direction: "INGRESS",
        action: "allow",
        match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(
          dest_ip_ranges: ["10.0.0.99/32"]
        )
      )
      policy = Google::Cloud::Compute::V1::FirewallPolicy.new(name: vpc_name, rules: [other_vm_rule])
      expect(nfp_client).to receive(:get).and_return(policy)

      # Should not try to delete the other VM's rule
      expect(nfp_client).not_to receive(:remove_rule)

      expect { nx.update_firewall_rules }.to exit({"msg" => "firewall rule is added"})
    end
  end
end
