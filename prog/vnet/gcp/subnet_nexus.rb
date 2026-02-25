# frozen_string_literal: true

require "google/cloud/compute/v1"
require "google/cloud/resource_manager/v3"
require_relative "../../../lib/gcp_lro"

class Prog::Vnet::Gcp::SubnetNexus < Prog::Base
  include GcpLro

  subject_is :private_subnet

  RFC1918_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].freeze
  # GCE internal IPv6 ranges used by dual-stack subnets (ULA space)
  GCE_INTERNAL_IPV6_RANGES = ["fd20::/20"].freeze

  # Priority assignments for firewall policy rules.
  # Lower number = higher priority. Range: 0–65535.
  DENY_RULE_BASE_PRIORITY = 65534
  ALLOW_SUBNET_BASE_PRIORITY = 1000

  def self.vpc_name(project)
    "ubicloud-proj-#{project.ubid}"
  end

  # Tag key short_name for a VPC (must be unique within the GCP project).
  # Used with purpose GCE_FIREWALL to create secure tags for firewall policies.
  def self.tag_key_short_name(project)
    vpc_name(project)
  end

  label def start
    register_deadline("wait", 5 * 60)
    hop_create_vpc
  end

  label def create_vpc
    begin
      credential.networks_client.get(
        project: gcp_project_id,
        network: gcp_vpc_name
      )
    rescue Google::Cloud::NotFoundError
      op = credential.networks_client.insert(
        project: gcp_project_id,
        network_resource: Google::Cloud::Compute::V1::Network.new(
          name: gcp_vpc_name,
          auto_create_subnetworks: false,
          routing_config: Google::Cloud::Compute::V1::NetworkRoutingConfig.new(
            routing_mode: "REGIONAL"
          )
        )
      )
      save_gcp_op(op.name, "global")
      hop_wait_create_vpc
    end

    hop_create_firewall_policy
  end

  label def wait_create_vpc
    op = poll_gcp_op
    nap 5 unless op.status == :DONE

    if op_error?(op)
      begin
        credential.networks_client.get(project: gcp_project_id, network: gcp_vpc_name)
        Clog.emit("GCP LRO error but resource exists",
          {gcp_lro_recovered: {resource: "VPC #{gcp_vpc_name}", error: op_error_message(op)}})
      rescue Google::Cloud::NotFoundError
        raise "GCP VPC #{gcp_vpc_name} creation failed: #{op_error_message(op)}"
      end
    end

    clear_gcp_op
    hop_create_firewall_policy
  end

  label def create_firewall_policy
    ensure_firewall_policy
    hop_create_tag_key
  end

  label def create_tag_key
    ensure_tag_key
    ensure_tag_value("vm")
    hop_create_vpc_deny_rules
  end

  label def create_vpc_deny_rules
    vm_tag_value_name = resolve_tag_value_name("vm")

    ensure_policy_rule(
      priority: DENY_RULE_BASE_PRIORITY,
      direction: "INGRESS",
      action: "deny",
      target_secure_tags: [vm_tag_value_name],
      src_ip_ranges: RFC1918_RANGES
    )

    ensure_policy_rule(
      priority: DENY_RULE_BASE_PRIORITY - 1,
      direction: "EGRESS",
      action: "deny",
      target_secure_tags: [vm_tag_value_name],
      dest_ip_ranges: RFC1918_RANGES
    )

    ensure_policy_rule(
      priority: DENY_RULE_BASE_PRIORITY - 2,
      direction: "INGRESS",
      action: "deny",
      target_secure_tags: [vm_tag_value_name],
      src_ip_ranges: GCE_INTERNAL_IPV6_RANGES
    )

    ensure_policy_rule(
      priority: DENY_RULE_BASE_PRIORITY - 3,
      direction: "EGRESS",
      action: "deny",
      target_secure_tags: [vm_tag_value_name],
      dest_ip_ranges: GCE_INTERNAL_IPV6_RANGES
    )

    hop_create_subnet
  end

  label def create_subnet
    subnet_name = "ubicloud-#{private_subnet.ubid}"
    begin
      credential.subnetworks_client.get(
        project: gcp_project_id,
        region: gcp_region,
        subnetwork: subnet_name
      )
    rescue Google::Cloud::NotFoundError
      op = credential.subnetworks_client.insert(
        project: gcp_project_id,
        region: gcp_region,
        subnetwork_resource: Google::Cloud::Compute::V1::Subnetwork.new(
          name: subnet_name,
          ip_cidr_range: private_subnet.net4.to_s,
          network: "projects/#{gcp_project_id}/global/networks/#{gcp_vpc_name}",
          private_ip_google_access: true,
          stack_type: "IPV4_IPV6",
          ipv6_access_type: "EXTERNAL"
        )
      )
      save_gcp_op(op.name, "region", gcp_region)
      hop_wait_create_subnet
    end

    hop_create_subnet_allow_rules
  end

  label def wait_create_subnet
    op = poll_gcp_op
    nap 5 unless op.status == :DONE

    subnet_name = "ubicloud-#{private_subnet.ubid}"
    if op_error?(op)
      begin
        credential.subnetworks_client.get(project: gcp_project_id, region: gcp_region, subnetwork: subnet_name)
        Clog.emit("GCP LRO error but resource exists",
          {gcp_lro_recovered: {resource: "subnet #{subnet_name}", error: op_error_message(op)}})
      rescue Google::Cloud::NotFoundError
        raise "GCP subnet #{subnet_name} creation failed: #{op_error_message(op)}"
      end
    end

    clear_gcp_op
    hop_create_subnet_allow_rules
  end

  label def create_subnet_allow_rules
    ensure_tag_value(subnet_tag)

    subnet_tag_value_name = resolve_tag_value_name(subnet_tag)

    # Allow same-subnet IPv4 egress (overrides the VPC-wide deny-egress)
    ensure_policy_rule(
      priority: subnet_allow_priority,
      direction: "EGRESS",
      action: "allow",
      target_secure_tags: [subnet_tag_value_name],
      dest_ip_ranges: [private_subnet.net4.to_s],
      layer4_configs: [{ip_protocol: "all"}]
    )

    # Allow same-subnet IPv6 egress (overrides VPC-wide deny-egress-ipv6)
    ensure_policy_rule(
      priority: subnet_allow_priority + 1,
      direction: "EGRESS",
      action: "allow",
      target_secure_tags: [subnet_tag_value_name],
      dest_ip_ranges: [private_subnet.net6.to_s],
      layer4_configs: [{ip_protocol: "all"}]
    )

    hop_wait
  end

  label def wait
    when_refresh_keys_set? do
      # GCP has no IPsec tunnels — nothing to rekey, just clear the semaphore
      decr_refresh_keys
    end

    when_update_firewall_rules_set? do
      private_subnet.vms.each(&:incr_update_firewall_rules)
      decr_update_firewall_rules
    end

    nap 10 * 60
  end

  label def destroy
    register_deadline("destroy", 5 * 60)
    decr_destroy
    private_subnet.remove_all_firewalls

    if private_subnet.nics.empty? && private_subnet.load_balancers.empty?
      delete_subnet_tag_value
      delete_subnet_policy_rules

      unless delete_gcp_subnet
        # GCE subnet still in use by a terminating instance — retry
        nap 5
      end
      maybe_delete_vpc
      private_subnet.destroy
      pop "subnet destroyed"
    else
      private_subnet.nics.map { |n| n.incr_destroy }
      private_subnet.load_balancers.map { |lb| lb.incr_destroy }
      nap rand(5..10)
    end
  end

  private

  # --- Firewall policy management ---

  def firewall_policy_name
    gcp_vpc_name
  end

  def ensure_firewall_policy
    credential.network_firewall_policies_client.get(
      project: gcp_project_id,
      firewall_policy: firewall_policy_name
    )
  rescue Google::Cloud::NotFoundError
    op = credential.network_firewall_policies_client.insert(
      project: gcp_project_id,
      firewall_policy_resource: Google::Cloud::Compute::V1::FirewallPolicy.new(
        name: firewall_policy_name,
        description: "Ubicloud network firewall policy for #{gcp_vpc_name}"
      )
    )
    wait_for_compute_global_op(op)

    # Associate the policy with the VPC network
    assoc_op = credential.network_firewall_policies_client.add_association(
      project: gcp_project_id,
      firewall_policy: firewall_policy_name,
      firewall_policy_association_resource: Google::Cloud::Compute::V1::FirewallPolicyAssociation.new(
        name: gcp_vpc_name,
        attachment_target: "projects/#{gcp_project_id}/global/networks/#{gcp_vpc_name}"
      )
    )
    wait_for_compute_global_op(assoc_op)
  end

  def ensure_policy_rule(priority:, direction:, action:, target_secure_tags:, src_ip_ranges: nil, dest_ip_ranges: nil, layer4_configs: nil)
    credential.network_firewall_policies_client.get_rule(
      project: gcp_project_id,
      firewall_policy: firewall_policy_name,
      priority:
    )
  rescue Google::Cloud::NotFoundError
    matcher_attrs = {}
    matcher_attrs[:src_ip_ranges] = src_ip_ranges if src_ip_ranges
    matcher_attrs[:dest_ip_ranges] = dest_ip_ranges if dest_ip_ranges

    matcher_attrs[:layer4_configs] = if layer4_configs
      layer4_configs.map { |cfg|
        Google::Cloud::Compute::V1::FirewallPolicyRuleMatcherLayer4Config.new(**cfg)
      }
    else
      [
        Google::Cloud::Compute::V1::FirewallPolicyRuleMatcherLayer4Config.new(ip_protocol: "all")
      ]
    end

    secure_tags = target_secure_tags.map { |tag_value_name|
      Google::Cloud::Compute::V1::FirewallPolicyRuleSecureTag.new(name: tag_value_name)
    }

    rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
      priority:,
      direction:,
      action:,
      match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(**matcher_attrs),
      target_secure_tags: secure_tags
    )

    op = credential.network_firewall_policies_client.add_rule(
      project: gcp_project_id,
      firewall_policy: firewall_policy_name,
      firewall_policy_rule_resource: rule
    )
    wait_for_compute_global_op(op)
  end

  # --- Tag management ---

  def tag_key_short_name
    @tag_key_short_name ||= self.class.tag_key_short_name(private_subnet.project)
  end

  def tag_key_parent
    "projects/#{gcp_project_id}"
  end

  def ensure_tag_key
    credential.tag_keys_client.get_namespaced_tag_key(
      name: "#{gcp_project_id}/#{tag_key_short_name}"
    )
  rescue Google::Cloud::NotFoundError
    op = credential.tag_keys_client.create_tag_key(
      tag_key: Google::Cloud::ResourceManager::V3::TagKey.new(
        parent: tag_key_parent,
        short_name: tag_key_short_name,
        description: "Ubicloud secure firewall tags for #{gcp_vpc_name}",
        purpose: :GCE_FIREWALL,
        purpose_data: {"network" => "#{tag_key_parent}/global/networks/#{gcp_vpc_name}"}
      )
    )
    op.wait_until_done!
    raise "Tag key creation failed: #{op.error.message}" if op.error?
  end

  def ensure_tag_value(short_name)
    tag_key = credential.tag_keys_client.get_namespaced_tag_key(
      name: "#{gcp_project_id}/#{tag_key_short_name}"
    )
    credential.tag_values_client.get_namespaced_tag_value(
      name: "#{gcp_project_id}/#{tag_key_short_name}/#{short_name}"
    )
  rescue Google::Cloud::NotFoundError
    tag_key ||= credential.tag_keys_client.get_namespaced_tag_key(
      name: "#{gcp_project_id}/#{tag_key_short_name}"
    )
    op = credential.tag_values_client.create_tag_value(
      tag_value: Google::Cloud::ResourceManager::V3::TagValue.new(
        parent: tag_key.name,
        short_name:,
        description: "Ubicloud tag value: #{short_name}"
      )
    )
    op.wait_until_done!
    raise "Tag value creation failed: #{op.error.message}" if op.error?
  end

  def resolve_tag_value_name(short_name)
    tv = credential.tag_values_client.get_namespaced_tag_value(
      name: "#{gcp_project_id}/#{tag_key_short_name}/#{short_name}"
    )
    tv.name
  end

  # --- Destroy helpers ---

  def delete_subnet_tag_value
    tv = credential.tag_values_client.get_namespaced_tag_value(
      name: "#{gcp_project_id}/#{tag_key_short_name}/#{subnet_tag}"
    )
    op = credential.tag_values_client.delete_tag_value(name: tv.name)
    op.wait_until_done!
  rescue Google::Cloud::NotFoundError
    # Already deleted
  end

  def delete_subnet_policy_rules
    [subnet_allow_priority, subnet_allow_priority + 1].each do |priority|
      credential.network_firewall_policies_client.remove_rule(
        project: gcp_project_id,
        firewall_policy: firewall_policy_name,
        priority:
      )
    rescue Google::Cloud::NotFoundError
      # Already deleted
    end
  rescue Google::Cloud::NotFoundError
    # Policy already deleted
  end

  def delete_gcp_subnet
    subnet_name = "ubicloud-#{private_subnet.ubid}"
    credential.subnetworks_client.delete(
      project: gcp_project_id,
      region: gcp_region,
      subnetwork: subnet_name
    )
    true
  rescue Google::Cloud::NotFoundError
    true # Already deleted
  rescue Google::Cloud::InvalidArgumentError => e
    raise unless e.message.include?("being used by")
    Clog.emit("GCP subnet still in use, retrying", {gcp_subnet_in_use: {subnet: subnet_name, error: e.message}})
    false
  end

  def maybe_delete_vpc
    project = private_subnet.project
    remaining = project.private_subnets_dataset.where(
      Sequel.lit("id != ? AND location_id IN (SELECT id FROM location WHERE provider = 'gcp')", private_subnet.id)
    ).count
    return if remaining > 0

    # Last GCP subnet in this project — clean up firewall policy, tags, and VPC
    delete_firewall_policy
    delete_tag_key
    delete_vpc_network
  end

  def delete_firewall_policy
    credential.network_firewall_policies_client.delete(
      project: gcp_project_id,
      firewall_policy: firewall_policy_name
    )
  rescue Google::Cloud::NotFoundError
    # Already deleted
  end

  def delete_tag_key
    tag_key = credential.tag_keys_client.get_namespaced_tag_key(
      name: "#{gcp_project_id}/#{tag_key_short_name}"
    )
    # Delete remaining tag values first
    credential.tag_values_client.list_tag_values(parent: tag_key.name).each do |tv|
      op = credential.tag_values_client.delete_tag_value(name: tv.name)
      op.wait_until_done!
    rescue Google::Cloud::NotFoundError
      # Already deleted
    end
    op = credential.tag_keys_client.delete_tag_key(name: tag_key.name)
    op.wait_until_done!
  rescue Google::Cloud::NotFoundError
    # Already deleted
  end

  def delete_vpc_network
    credential.networks_client.delete(project: gcp_project_id, network: gcp_vpc_name)
  rescue Google::Cloud::NotFoundError
    # Already deleted
  end

  # --- Shared helpers ---

  def subnet_tag
    "ps-#{private_subnet.ubid}"
  end

  # Deterministic priority for subnet allow rules. Each subnet gets a unique
  # pair of priorities (IPv4 egress, IPv6 egress) based on a hash of its ubid.
  def subnet_allow_priority
    @subnet_allow_priority ||= ALLOW_SUBNET_BASE_PRIORITY + (private_subnet.ubid.hash.abs % 30000) * 2
  end

  def gcp_vpc_name
    @gcp_vpc_name ||= self.class.vpc_name(private_subnet.project)
  end

  def credential
    @credential ||= private_subnet.location.location_credential
  end

  def gcp_project_id
    @gcp_project_id ||= credential.project_id
  end

  def gcp_region
    @gcp_region ||= private_subnet.location.name.delete_prefix("gcp-")
  end

  def wait_for_compute_global_op(op)
    # Poll until done, with a short timeout for inline waits
    return unless op.respond_to?(:name)
    5.times do
      result = credential.global_operations_client.get(
        project: gcp_project_id,
        operation: op.name
      )
      return if result.status == :DONE
      sleep 1
    end
  end
end
