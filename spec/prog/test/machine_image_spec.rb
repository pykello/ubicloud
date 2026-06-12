# frozen_string_literal: true

require_relative "../../model/spec_helper"

RSpec.describe Prog::Test::MachineImage do
  subject(:mi_test) { described_class.new(st) }

  let(:st) { described_class.assemble(version: "20260601") }
  let(:archive_kek) { StorageKeyEncryptionKey.create_random(auth_data: "archive-kek") }

  before do
    allow(Config).to receive_messages(
      e2e_machine_images_r2_endpoint: "https://r2.example.com",
      e2e_machine_images_r2_bucket: "e2e-test",
      e2e_machine_images_r2_access_key: "ak",
      e2e_machine_images_r2_secret_key: "sk",
      e2e_ubuntu_noble_sha256sum: "deadbeef",
    )
  end

  def seed_metal(status:, version: "20260601")
    miv = MachineImageVersion.create(machine_image_id: described_class::UBUNTU_NOBLE_MI_ID,
      version:, actual_size_mib: 1024)
    store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
      location_id: described_class::LOCATION_ID)
    archive_size = (status == "ready") ? 1 : nil
    MachineImageVersionMetal.create_with_id(miv, status:, archive_size_mib: archive_size,
      archive_kek_id: archive_kek.id, store_id: store.id, store_prefix: "p")
    miv
  end

  describe "#start" do
    it "hops to bootstrap" do
      expect { mi_test.start }.to hop("bootstrap")
    end
  end

  describe "#bootstrap" do
    it "creates project, store, machine image, subnet when none exist" do
      expect { mi_test.bootstrap }.to hop("wipe_stale")

      project = Project[described_class::SERVICE_PROJECT_ID]
      expect(project.name).to eq("MachineImage-E2E-Service")
      store = MachineImageStore.first(project_id: project.id, location_id: described_class::LOCATION_ID)
      expect(store).to have_attributes(provider: "r2", region: "auto", endpoint: "https://r2.example.com",
        bucket: "e2e-test", access_key: "ak", secret_key: "sk")
      mi = MachineImage[described_class::UBUNTU_NOBLE_MI_ID]
      expect(mi).to have_attributes(name: "ubuntu-noble", arch: "x64",
        project_id: project.id, location_id: described_class::LOCATION_ID)
      subnet = project.private_subnets_dataset.first(location_id: described_class::LOCATION_ID,
        name: described_class::SUBNET_NAME)
      expect(subnet).not_to be_nil
      expect(mi_test.subnet_id).to eq(subnet.id)
    end

    it "is idempotent — reuses existing project, store, machine image, subnet" do
      expect { mi_test.bootstrap }.to hop("wipe_stale")
      counts_before = [Project.count, MachineImageStore.count, MachineImage.count, PrivateSubnet.count]

      expect { mi_test.bootstrap }.to hop("wipe_stale")
      expect([Project.count, MachineImageStore.count, MachineImage.count, PrivateSubnet.count])
        .to eq(counts_before)
    end
  end

  describe "#wipe_stale" do
    before { expect { mi_test.bootstrap }.to hop("wipe_stale") }

    it "increments the destroy semaphore when a 'creating' MIV for the version exists" do
      miv = seed_metal(status: "creating")
      Strand.create_with_id(miv, prog: "MachineImage::VersionMetalNexus", label: "archive")

      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(miv.metal.reload.destroy_set?).to be(true)
    end

    it "leaves the MIV alone when it is already 'ready'" do
      miv = seed_metal(status: "ready")

      expect { mi_test.wipe_stale }.to hop("wait_wipe")
      expect(miv.metal.reload.destroy_set?).to be(false)
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

    it "hops to create_from_url when no MIV for the version exists" do
      expect { mi_test.wait_wipe }.to hop("create_from_url")
    end

    it "hops to assemble_verify_vm when the MIV for the version is ready (skips create)" do
      seed_metal(status: "ready")
      expect { mi_test.wait_wipe }.to hop("assemble_verify_vm")
    end

    it "naps while a destroy is still in flight" do
      seed_metal(status: "destroying")
      expect { mi_test.wait_wipe }.to nap(5)
    end

    it "naps while a failed MIV is still being wiped" do
      seed_metal(status: "failed")
      expect { mi_test.wait_wipe }.to nap(5)
    end
  end

  describe "#create_from_url" do
    before { expect { mi_test.bootstrap }.to hop("wipe_stale") }

    it "calls VersionMetalNexus.assemble_from_url with the derived URL and the configured sha256sum" do
      mi = MachineImage[described_class::UBUNTU_NOBLE_MI_ID]
      store = MachineImageStore.first(project_id: described_class::SERVICE_PROJECT_ID,
        location_id: described_class::LOCATION_ID)

      expected_url = "https://cloud-images.ubuntu.com/releases/noble/release-20260601/ubuntu-24.04-server-cloudimg-amd64.img"
      expect(Prog::MachineImage::VersionMetalNexus).to receive(:assemble_from_url)
        .with(mi, "20260601", expected_url, "deadbeef", store)
      expect { mi_test.create_from_url }.to hop("wait_create")
    end
  end

  describe "#wait_create" do
    before { expect { mi_test.bootstrap }.to hop("wipe_stale") }

    it "naps while the metal version isn't ready yet" do
      seed_metal(status: "creating")
      expect { mi_test.wait_create }.to nap(30)
    end

    it "naps when no MIV for the version exists yet" do
      expect { mi_test.wait_create }.to nap(30)
    end

    it "hops to assemble_verify_vm once the metal version is ready" do
      seed_metal(status: "ready")
      expect { mi_test.wait_create }.to hop("assemble_verify_vm")
    end

    it "fails the test when the metal version archive ends in 'failed'" do
      seed_metal(status: "failed")
      expect { mi_test.wait_create }.to hop("failed")
      expect(mi_test.strand.reload.exitval).to eq({"msg" => "machine image archive failed"})
    end
  end

  describe "#assemble_verify_vm" do
    before do
      expect { mi_test.bootstrap }.to hop("wipe_stale")
      seed_metal(status: "ready")
    end

    it "assembles a VM whose boot_image is the explicit ubuntu-noble@<version> reference" do
      expect { mi_test.assemble_verify_vm }.to hop("wait_verify_vm")
      expect(Vm[mi_test.verify_vm_id].boot_image).to eq("ubuntu-noble@20260601")
    end
  end

  describe "#wait_verify_vm" do
    it "naps while the verify VM isn't running" do
      vm = create_vm(display_state: "creating")
      refresh_frame(mi_test, new_values: {"verify_vm_id" => vm.id})
      expect { mi_test.wait_verify_vm }.to nap(10)
    end

    it "hops to verify_vm once the verify VM is running" do
      vm = create_vm(display_state: "running")
      refresh_frame(mi_test, new_values: {"verify_vm_id" => vm.id})
      expect { mi_test.wait_verify_vm }.to hop("verify_vm")
    end
  end

  describe "#verify_vm" do
    it "buds Prog::Test::Vm against the verify VM" do
      vm = create_vm
      refresh_frame(mi_test, new_values: {"verify_vm_id" => vm.id})
      expect { mi_test.verify_vm }.to hop("wait_verify_smoke_checks")
      children = st.children_dataset.where(prog: "Test::Vm").all
      expect(children.map { it.stack.first.values_at("subject_id", "first_boot") })
        .to contain_exactly([vm.id, true])
    end
  end

  describe "#wait_verify_smoke_checks" do
    it "hops to cleanup once children are reaped" do
      expect { mi_test.wait_verify_smoke_checks }.to hop("cleanup")
    end
  end

  describe "#cleanup" do
    it "increments destroy on the verify VM" do
      vm = create_vm
      Strand.create_with_id(vm, prog: "Vm::Nexus", label: "wait")
      refresh_frame(mi_test, new_values: {"verify_vm_id" => vm.id})
      expect { mi_test.cleanup }.to hop("wait_cleanup")
      expect(vm.reload.destroy_set?).to be true
    end

    it "still hops to wait_cleanup when the verify VM is already gone" do
      refresh_frame(mi_test, new_values: {"verify_vm_id" => "00000000-0000-0000-0000-000000000000"})
      expect { mi_test.cleanup }.to hop("wait_cleanup")
    end
  end

  describe "#wait_cleanup" do
    it "naps while the verify VM still exists" do
      vm = create_vm
      refresh_frame(mi_test, new_values: {"verify_vm_id" => vm.id})
      expect { mi_test.wait_cleanup }.to nap(5)
    end

    it "hops to finish once the verify VM is gone" do
      refresh_frame(mi_test, new_values: {"verify_vm_id" => "00000000-0000-0000-0000-000000000000"})
      expect { mi_test.wait_cleanup }.to hop("finish")
    end
  end

  describe "#finish" do
    it "pops" do
      expect { mi_test.finish }.to exit({"msg" => "MachineImage E2E finished!"})
    end
  end
end
