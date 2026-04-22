# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe Clover, "machine-image" do
  let(:user) { create_account }
  let(:project) {
    p = project_with_default_policy(user)
    p.set_ff_machine_image(true)
    p
  }
  let(:location_id) { Location[display_name: TEST_LOCATION].id }
  let(:mi_version_metal) { create_machine_image_version_metal(project_id: project.id, location_id:) }
  let(:mi) { mi_version_metal.machine_image_version.machine_image }

  before { login_api }

  describe "delete" do
    it "returns 400 when a VM is using a version" do
      vm_host = create_vm_host
      vhost = create_vhost_block_backend(allocation_weight: 50, vm_host_id: vm_host.id)
      vm = create_vm(vm_host_id: vm_host.id, project_id: project.id)
      sd = StorageDevice.create(name: "vda", total_storage_gib: 100, available_storage_gib: 50, vm_host_id: vm_host.id)
      VmStorageVolume.create(
        vm_id: vm.id, boot: true, size_gib: 5, disk_index: 0,
        storage_device_id: sd.id, vhost_block_backend_id: vhost.id,
        key_encryption_key_1_id: StorageKeyEncryptionKey.create_random(auth_data: "k1").id,
        machine_image_version_id: mi_version_metal.machine_image_version.id,
        vring_workers: 1,
      )

      delete "/project/#{project.ubid}/location/#{TEST_LOCATION}/machine-image/#{mi.name}"

      expect(last_response).to have_api_error(400, "VMs are still using this machine image")
    end

    it "schedules async destruction when versions with metal exist" do
      mi_version_metal

      expect {
        delete "/project/#{project.ubid}/location/#{TEST_LOCATION}/machine-image/#{mi.name}"
      }.to change { Strand.where(prog: "MachineImage::DestroyVersionMetal").count }.by(1)

      expect(last_response.status).to eq(204)
      expect(mi.reload.latest_version_id).to be_nil
      expect(mi.exists?).to be true
    end

    it "destroys the machine image synchronously when it has no versions with metal" do
      empty_mi = MachineImage.create(name: "empty-mi", project_id: project.id, arch: "x64", location_id:)

      delete "/project/#{project.ubid}/location/#{TEST_LOCATION}/machine-image/empty-mi"

      expect(last_response.status).to eq(204)
      expect(empty_mi.exists?).to be false
    end
  end
end
