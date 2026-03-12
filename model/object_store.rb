# frozen_string_literal: true

require_relative "../model"
require "aws-sdk-s3"

class ObjectStore < Sequel::Model
  plugin ResourceMethods, encrypted_columns: [:access_key, :secret_key, :cf_api_token]

  def s3_client
    Aws::S3::Client.new(
      region: "auto",
      endpoint: url,
      access_key_id: access_key,
      secret_access_key: secret_key
    )
  end

  def generate_temp_credentials(bucket:, permission: "object-read-write", ttl_seconds: 86400)
    fail "Cloudflare credentials required for temp credential generation" unless cf_account_id && cf_api_token

    cloudflare_client = CloudflareClient.new(cf_api_token)
    cloudflare_client.generate_temp_credentials(
      account_id: cf_account_id,
      parent_access_key_id: access_key,
      bucket:,
      permission:,
      ttl_seconds:
    )
  end
end
