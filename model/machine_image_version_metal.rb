# frozen_string_literal: true

require_relative "../model"

class MachineImageVersionMetal < Sequel::Model
  many_to_one :machine_image_version, key: :id, read_only: true, is_used: true
  many_to_one :key_encryption_key_1, class: :StorageKeyEncryptionKey

  plugin ResourceMethods, etc_type: true
end
