# frozen_string_literal: true

Sequel.migration do
  up do
    run(<<~SQL)
      INSERT INTO strand (id, prog, label)
      SELECT mvm.id, 'MachineImage::VersionMetalNexus', 'wait'
      FROM machine_image_version_metal mvm
      LEFT JOIN strand s ON s.id = mvm.id
      WHERE mvm.status = 'ready' AND s.id IS NULL
    SQL
  end

  down do
    run(<<~SQL)
      DELETE FROM strand
      WHERE prog = 'MachineImage::VersionMetalNexus' AND label = 'wait'
    SQL
  end
end
