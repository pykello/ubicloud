# frozen_string_literal: true

require "google/cloud/compute/v1"
require "google/cloud/resource_manager/v3"

class PrivateSubnet < Sequel::Model
  module Gcp
    private

    def gcp_connect_subnet(subnet)
      ConnectedSubnet.create(subnet_hash(subnet))
      create_cross_subnet_rules(subnet)
    end

    def gcp_disconnect_subnet(subnet)
      ConnectedSubnet.where(subnet_hash(subnet)).destroy
      delete_cross_subnet_rules(subnet)
    end

    def create_cross_subnet_rules(other)
      cred = location.location_credential
      project_id = cred.project_id
      policy_name = Prog::Vnet::Gcp::SubnetNexus.vpc_name(project)
      tag_key_short = Prog::Vnet::Gcp::SubnetNexus.tag_key_short_name(project)

      directions = %w[egress ingress]
      [self, other].each do |src|
        dst = (src == self) ? other : self

        src_tag_value = cred.tag_values_client.get_namespaced_tag_value(
          name: "#{project_id}/#{tag_key_short}/ps-#{src.ubid}"
        )

        directions.each do |dir|
          priority = cross_subnet_rule_priority(src, dst, dir)
          begin
            cred.network_firewall_policies_client.get_rule(
              project: project_id,
              firewall_policy: policy_name,
              priority:
            )
          rescue Google::Cloud::NotFoundError
            matcher_attrs = {
              layer4_configs: [
                Google::Cloud::Compute::V1::FirewallPolicyRuleMatcherLayer4Config.new(ip_protocol: "all")
              ]
            }
            if dir == "egress"
              matcher_attrs[:dest_ip_ranges] = [dst.net4.to_s]
            else
              matcher_attrs[:src_ip_ranges] = [dst.net4.to_s]
            end

            rule = Google::Cloud::Compute::V1::FirewallPolicyRule.new(
              priority:,
              direction: dir.upcase,
              action: "allow",
              match: Google::Cloud::Compute::V1::FirewallPolicyRuleMatcher.new(**matcher_attrs),
              target_secure_tags: [
                Google::Cloud::Compute::V1::FirewallPolicyRuleSecureTag.new(name: src_tag_value.name)
              ]
            )
            cred.network_firewall_policies_client.add_rule(
              project: project_id,
              firewall_policy: policy_name,
              firewall_policy_rule_resource: rule
            )
          end
        end
      end
    end

    def delete_cross_subnet_rules(other)
      cred = location.location_credential
      project_id = cred.project_id
      policy_name = Prog::Vnet::Gcp::SubnetNexus.vpc_name(project)

      directions = %w[egress ingress]
      [self, other].each do |src|
        dst = (src == self) ? other : self
        directions.each do |dir|
          priority = cross_subnet_rule_priority(src, dst, dir)
          cred.network_firewall_policies_client.remove_rule(
            project: project_id,
            firewall_policy: policy_name,
            priority:
          )
        rescue Google::Cloud::NotFoundError
          # Already deleted
        end
      end
    end

    def cross_subnet_rule_priority(src, dst, direction)
      hash_input = "#{src.ubid}-#{dst.ubid}-#{direction}"
      2000 + (hash_input.hash.abs % 8000)
    end
  end
end

# Table: private_subnet
# Columns:
#  id            | uuid                     | PRIMARY KEY
#  net6          | cidr                     | NOT NULL
#  net4          | cidr                     | NOT NULL
#  state         | text                     | NOT NULL DEFAULT 'creating'::text
#  name          | text                     | NOT NULL
#  last_rekey_at | timestamp with time zone | NOT NULL DEFAULT now()
#  project_id    | uuid                     | NOT NULL
#  location_id   | uuid                     | NOT NULL
# Indexes:
#  vm_private_subnet_pkey                          | PRIMARY KEY btree (id)
#  private_subnet_project_id_location_id_name_uidx | UNIQUE btree (project_id, location_id, name)
# Foreign key constraints:
#  private_subnet_location_id_fkey | (location_id) REFERENCES location(id)
#  private_subnet_project_id_fkey  | (project_id) REFERENCES project(id)
# Referenced By:
#  connected_subnet            | connected_subnet_subnet_id_1_fkey                | (subnet_id_1) REFERENCES private_subnet(id)
#  connected_subnet            | connected_subnet_subnet_id_2_fkey                | (subnet_id_2) REFERENCES private_subnet(id)
#  firewalls_private_subnets   | firewalls_private_subnets_private_subnet_id_fkey | (private_subnet_id) REFERENCES private_subnet(id)
#  inference_endpoint          | inference_endpoint_private_subnet_id_fkey        | (private_subnet_id) REFERENCES private_subnet(id)
#  inference_router            | inference_router_private_subnet_id_fkey          | (private_subnet_id) REFERENCES private_subnet(id)
#  kubernetes_cluster          | kubernetes_cluster_private_subnet_id_fkey        | (private_subnet_id) REFERENCES private_subnet(id)
#  load_balancer               | load_balancer_private_subnet_id_fkey             | (private_subnet_id) REFERENCES private_subnet(id)
#  minio_cluster               | minio_cluster_private_subnet_id_fkey             | (private_subnet_id) REFERENCES private_subnet(id)
#  nic                         | nic_private_subnet_id_fkey                       | (private_subnet_id) REFERENCES private_subnet(id)
#  private_subnet_aws_resource | private_subnet_aws_resource_id_fkey              | (id) REFERENCES private_subnet(id)
#  victoria_metrics_resource   | victoria_metrics_resource_private_subnet_id_fkey | (private_subnet_id) REFERENCES private_subnet(id)
