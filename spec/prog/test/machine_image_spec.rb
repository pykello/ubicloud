# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::Test::MachineImage do
  subject(:mi_test) { described_class.new(st) }

  let(:st) { described_class.assemble(version: "20260601.1.0") }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "archive-kek") }

  before do
    allow(Config).to receive_messages(
      e2e_machine_images_r2_endpoint: "https://r2.example.com",
      e2e_machine_images_r2_bucket: "e2e-test",
      e2e_machine_images_r2_access_key: "ak",
      e2e_machine_images_r2_secret_key: "sk",
    )
  end

  describe "#start" do
    it "hops to bootstrap" do
      expect { mi_test.start }.to hop("bootstrap")
    end
  end

  describe "#bootstrap" do
    it "creates project, store and machine image when none exist" do
      expect { mi_test.bootstrap }.to hop("wipe_stale")

      project = Project[described_class::SERVICE_PROJECT_ID]
      expect(project.name).to eq("MachineImage-E2E-Service")
      store = MachineImageStore.first(project_id: project.id, location_id: described_class::LOCATION_ID)
      expect(store).to have_attributes(provider: "r2", region: "auto", endpoint: "https://r2.example.com",
        bucket: "e2e-test", access_key: "ak", secret_key: "sk")
      mi = MachineImage[described_class::UBUNTU_NOBLE_MI_ID]
      expect(mi).to have_attributes(name: "ubuntu-noble", arch: "x64",
        project_id: project.id, location_id: described_class::LOCATION_ID)
    end

    it "is idempotent — reuses existing project, store, machine image" do
      expect { mi_test.bootstrap }.to hop("wipe_stale")
      project_count_before = Project.count
      store_count_before = MachineImageStore.count
      mi_count_before = MachineImage.count

      expect { mi_test.bootstrap }.to hop("wipe_stale")
      expect(Project.count).to eq(project_count_before)
      expect(MachineImageStore.count).to eq(store_count_before)
      expect(MachineImage.count).to eq(mi_count_before)
    end
  end

  describe "#wipe_stale" do
    before { expect { mi_test.bootstrap }.to hop("wipe_stale") }

    it "increments the destroy semaphore when a 'creating' MIV for the version exists" do
      miv = MachineImageVersion.create(machine_image_id: described_class::UBUNTU_NOBLE_MI_ID,
        version: "20260601.1.0", actual_size_mib: 1024)
      store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
        location_id: described_class::LOCATION_ID)
      metal = MachineImageVersionMetal.create_with_id(miv, status: "creating",
        archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")
      Strand.create_with_id(miv, prog: "MachineImage::VersionMetalNexus", label: "archive")

      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(metal.reload.destroy_set?).to be(true)
    end

    it "leaves the MIV alone when it is already 'ready'" do
      miv = MachineImageVersion.create(machine_image_id: described_class::UBUNTU_NOBLE_MI_ID,
        version: "20260601.1.0", actual_size_mib: 1024)
      store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
        location_id: described_class::LOCATION_ID)
      metal = MachineImageVersionMetal.create_with_id(miv, status: "ready", archive_size_mib: 1,
        archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")

      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(metal.reload.destroy_set?).to be(false)
    end

    it "increments the destroy semaphore when a 'failed' MIV from a prior run is left over" do
      miv = seed_metal(status: "failed")
      Strand.create_with_id(miv, prog: "MachineImage::VersionMetalNexus", label: "failed")

      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(miv.metal.reload.destroy_set?).to be(true)
    end

    it "does nothing when no MIV for the version exists yet" do
      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(Semaphore.where(name: "destroy").count).to eq(0)
    end
  end

  describe "#wait_wipe" do
    before { expect { mi_test.bootstrap }.to hop("wipe_stale") }

    it "pops when no stale MIV is in flight" do
      expect { mi_test.wait_wipe }.to exit({"msg" => "MachineImage E2E bootstrap finished!"})
    end

    it "pops when the MIV for the version is ready" do
      miv = MachineImageVersion.create(machine_image_id: described_class::UBUNTU_NOBLE_MI_ID,
        version: "20260601.1.0", actual_size_mib: 1024)
      store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
        location_id: described_class::LOCATION_ID)
      MachineImageVersionMetal.create_with_id(miv, status: "ready", archive_size_mib: 1,
        archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")

      expect { mi_test.wait_wipe }.to exit({"msg" => "MachineImage E2E bootstrap finished!"})
    end

    it "naps while a destroy is still in flight" do
      miv = MachineImageVersion.create(machine_image_id: described_class::UBUNTU_NOBLE_MI_ID,
        version: "20260601.1.0", actual_size_mib: 1024)
      store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
        location_id: described_class::LOCATION_ID)
      MachineImageVersionMetal.create_with_id(miv, status: "destroying", archive_size_mib: nil,
        archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")

      expect { mi_test.wait_wipe }.to nap(5)
    end

    it "naps while a failed MIV is still being wiped" do
      seed_metal(status: "failed")
      expect { mi_test.wait_wipe }.to nap(5)
    end
  end
end
