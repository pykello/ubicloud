# frozen_string_literal: true

class Clover
  def machine_image_list
    dataset = dataset_authorize(@project.machine_images_dataset, "MachineImage:view").eager(:location, :latest_version)

    dataset = dataset.where(location_id: @location.id) if @location
    paginated_result(dataset, Serializers::MachineImage)
  end

  def machine_image_post(name)
    project = @project
    authorize("MachineImage:create", project)

    source_vm_id = typecast_params.nonempty_str!("vm")
    version = typecast_params.nonempty_str("version") || Time.now.strftime("%Y%m%d%H%M%S")
    destroy_source = typecast_params.bool("destroy_source")

    source_vm = project.vms_dataset.first(id: UBID.to_uuid(source_vm_id))
    unless source_vm
      raise CloverError.new(400, "InvalidRequest", "Source VM not found")
    end

    store = MachineImageStore.where(project_id: project.id, location_id: @location.id).first
    unless store
      raise CloverError.new(400, "InvalidRequest", "No machine image store configured for this location")
    end

    mi = nil
    DB.transaction do
      mi = MachineImage.create(
        name:,
        arch: source_vm.arch,
        project_id: project.id,
        location_id: @location.id,
      )

      Prog::MachineImage::CreateVersionMetal.assemble(mi, version, source_vm, store, destroy_source_after: !!destroy_source)

      audit_log(mi, "create")
    end

    Serializers::MachineImage.serialize(mi, {detailed: true})
  end

  def machine_image_destroy(mi)
    authorize("MachineImage:delete", mi)

    versions = mi.versions_dataset.eager(metal: :vm_storage_volumes).all
    in_use = versions.select { |v| v.metal && !v.metal.vm_storage_volumes.empty? }
    unless in_use.empty?
      raise CloverError.new(400, "InvalidRequest", "VMs are still using this machine image")
    end

    DB.transaction do
      # Nullify latest_version_id so DestroyVersionMetal.assemble doesn't refuse the
      # latest version. The final version's update_database label also uses this as
      # the signal to destroy the MachineImage row itself.
      mi.update(latest_version_id: nil)
      versions.each do |v|
        Prog::MachineImage::DestroyVersionMetal.assemble(v.metal) if v.metal
      end
      audit_log(mi, "destroy")
    end

    # If there were no versions (or none with metal), destroy the MI record now;
    # otherwise the last version's update_database label will clean it up.
    mi.destroy if versions.none? { |v| v.metal }

    204
  end
end
