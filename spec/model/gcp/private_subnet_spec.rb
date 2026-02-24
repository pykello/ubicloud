# frozen_string_literal: true

require "google/cloud/compute/v1"
require_relative "../spec_helper"

RSpec.describe PrivateSubnet do
  let(:project) { Project.create(name: "gcp-ps-test") }
  let(:location) {
    Location.create(name: "gcp-us-central1", provider: "gcp",
      display_name: "GCP US Central 1", ui_name: "GCP US Central 1", visible: true)
  }
  let(:location_credential) {
    LocationCredential.create_with_id(location.id,
      project_id: "test-project",
      service_account_email: "test@test-project.iam.gserviceaccount.com",
      credentials_json: '{"type":"service_account","project_id":"test-project"}')
  }
  let(:firewalls_client) { instance_double(Google::Cloud::Compute::V1::Firewalls::Rest::Client) }

  let(:subnet1) {
    described_class.create(
      name: "ps1", location_id: location.id, project_id: project.id,
      net6: "fd10:9b0b:6b4b:8fbb::/64", net4: "10.0.0.0/26", state: "active"
    ) { it.id = SecureRandom.uuid }
  }

  let(:subnet2) {
    described_class.create(
      name: "ps2", location_id: location.id, project_id: project.id,
      net6: "fd10:9b0b:6b4b:9fbb::/64", net4: "10.0.1.0/26", state: "active"
    ) { it.id = SecureRandom.uuid }
  }

  before do
    location_credential
    allow_any_instance_of(LocationCredential).to receive(:firewalls_client).and_return(firewalls_client)
  end

  context "with GCP provider" do
    describe "#connect_subnet" do
      it "creates ConnectedSubnet and cross-subnet firewall rules" do
        # 4 combinations: 2 subnets × 2 directions
        # For each: get (raises NotFoundError) → insert
        expect(firewalls_client).to receive(:get).exactly(4).times
          .and_raise(Google::Cloud::NotFoundError.new("not found"))
        expect(firewalls_client).to receive(:insert).exactly(4).times

        subnet1.connect_subnet(subnet2)
        id1, id2 = [subnet1, subnet2].sort_by(&:id).map(&:id)
        expect(ConnectedSubnet.where(subnet_id_1: id1, subnet_id_2: id2).count).to eq(1)
      end

      it "skips creating rules that already exist" do
        expect(firewalls_client).to receive(:get).exactly(4).times
          .and_return(Google::Cloud::Compute::V1::Firewall.new)
        expect(firewalls_client).not_to receive(:insert)

        subnet1.connect_subnet(subnet2)
      end

      it "creates rules with correct direction attributes" do
        created_rules = []
        expect(firewalls_client).to receive(:get).exactly(4).times
          .and_raise(Google::Cloud::NotFoundError.new("not found"))
        expect(firewalls_client).to receive(:insert).exactly(4).times do |args|
          fw = args[:firewall_resource]
          created_rules << {name: fw.name, direction: fw.direction,
                            target_tags: fw.target_tags.to_a,
                            source_ranges: fw.source_ranges.to_a,
                            destination_ranges: fw.destination_ranges.to_a}
        end

        subnet1.connect_subnet(subnet2)

        egress_rules = created_rules.select { |r| r[:direction] == "EGRESS" }
        ingress_rules = created_rules.select { |r| r[:direction] == "INGRESS" }
        expect(egress_rules.length).to eq(2)
        expect(ingress_rules.length).to eq(2)

        # Check egress rules have destination_ranges
        egress_rules.each do |r|
          expect(r[:destination_ranges]).not_to be_empty
        end

        # Check ingress rules have source_ranges
        ingress_rules.each do |r|
          expect(r[:source_ranges]).not_to be_empty
        end
      end
    end

    describe "#disconnect_subnet" do
      def sorted_subnet_ids(s1, s2)
        [s1, s2].sort_by(&:id).map(&:id)
      end

      it "deletes ConnectedSubnet and cross-subnet firewall rules" do
        id1, id2 = sorted_subnet_ids(subnet1, subnet2)
        ConnectedSubnet.create(subnet_id_1: id1, subnet_id_2: id2)
        expect(firewalls_client).to receive(:delete).exactly(4).times

        subnet1.disconnect_subnet(subnet2)
        expect(ConnectedSubnet.where(subnet_id_1: id1, subnet_id_2: id2).count).to eq(0)
      end

      it "handles NotFoundError when rules are already deleted" do
        id1, id2 = sorted_subnet_ids(subnet1, subnet2)
        ConnectedSubnet.create(subnet_id_1: id1, subnet_id_2: id2)
        expect(firewalls_client).to receive(:delete).exactly(4).times
          .and_raise(Google::Cloud::NotFoundError.new("not found"))

        expect { subnet1.disconnect_subnet(subnet2) }.not_to raise_error
      end
    end
  end
end
