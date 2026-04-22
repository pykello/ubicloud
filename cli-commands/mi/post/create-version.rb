# frozen_string_literal: true

UbiCli.on("mi").run_on("create-version") do
  desc "Create a new version of a machine image from a stopped VM"

  options("ubi mi (location/mi-name | mi-id) create-version [options] version (vm-name | vm-id)", key: :mi_create_version) do
    on("-d", "--destroy-source", "destroy the source VM after capture")
  end

  args 2

  run do |version, vm_ref, opts|
    params = underscore_keys(opts[:mi_create_version])
    result = sdk_object.create_version(version, vm: convert_name_to_id(sdk.vm, vm_ref), destroy_source: params[:destroy_source])
    response("Machine image version created with id: #{result.id}")
  end
end
