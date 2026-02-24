# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe Location do
  let(:location) {
    described_class.create(name: "gcp-us-central1", provider: "gcp",
      display_name: "GCP US Central 1", ui_name: "GCP US Central 1", visible: true)
  }
  let(:location_credential) {
    LocationCredential.create_with_id(location.id,
      project_id: "test-project",
      service_account_email: "test@test-project.iam.gserviceaccount.com",
      credentials_json: '{"type":"service_account","project_id":"test-project"}')
  }

  context "with GCP provider" do
    describe "#pg_gce_image" do
      before { location_credential }

      it "returns a GCE image path when a matching PgGceImage exists" do
        PgGceImage.create_with_id(SecureRandom.uuid,
          gcp_project_id: "test-project",
          gce_image_name: "postgres-ubuntu-2404-x64-20260218",
          pg_version: "17",
          arch: "x64")

        expect(location.pg_gce_image("17", "x64")).to eq(
          "projects/test-project/global/images/postgres-ubuntu-2404-x64-20260218"
        )
      end

      it "raises when no matching PgGceImage is found" do
        expect { location.pg_gce_image("17", "x64") }.to raise_error(
          RuntimeError, /No GCE image found for PostgreSQL 17 \(x64\)/
        )
      end
    end

    describe "#pg_boot_image" do
      before { location_credential }

      it "delegates to pg_gce_image" do
        PgGceImage.create_with_id(SecureRandom.uuid,
          gcp_project_id: "test-project",
          gce_image_name: "postgres-ubuntu-2404-arm64-20260218",
          pg_version: "17",
          arch: "arm64")

        expect(location.send(:gcp_pg_boot_image, "17", "arm64", "standard")).to eq(
          "projects/test-project/global/images/postgres-ubuntu-2404-arm64-20260218"
        )
      end
    end

    describe "#azs" do
      it "raises an error because azs is only for AWS locations" do
        expect { location.send(:gcp_azs) }.to raise_error(RuntimeError, /azs is only valid for aws locations/)
      end
    end
  end
end
