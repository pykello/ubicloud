# frozen_string_literal: true

require "aws-sdk-s3"
require "json"

# Copies all objects under a given prefix from one S3-compatible store to
# another. Designed to be invoked by host/bin/copy-archive (typically as a
# daemonizer2 unit) so that long-running data transfer happens out-of-band
# from clover Ruby workers.
class StorageCopy
  PAGE_SIZE = 1000
  REQUIRED_KEYS = %w[bucket prefix region endpoint access_key_id secret_access_key].freeze

  def initialize(source_conf, target_conf, stats_file)
    StorageCopy.validate_conf(source_conf, "source_conf")
    StorageCopy.validate_conf(target_conf, "target_conf")
    @source_conf = source_conf
    @target_conf = target_conf
    @stats_file = stats_file
  end

  def self.validate_conf(conf, name)
    REQUIRED_KEYS.each do |k|
      fail "missing #{k} in #{name}" unless conf[k]
    end
  end

  def copy
    source_client = StorageCopy.build_client(@source_conf)
    target_client = StorageCopy.build_client(@target_conf)

    total_bytes = 0
    total_objects = 0
    continuation_token = nil
    source_prefix = @source_conf["prefix"]
    target_prefix = @target_conf["prefix"]

    loop do
      list_kwargs = {
        bucket: @source_conf["bucket"],
        prefix: source_prefix,
        max_keys: PAGE_SIZE,
      }
      list_kwargs[:continuation_token] = continuation_token if continuation_token
      page = source_client.list_objects_v2(**list_kwargs)

      page.contents.each do |obj|
        relative = obj.key.delete_prefix("#{source_prefix}/")
        target_key = "#{target_prefix}/#{relative}"

        get_resp = source_client.get_object(bucket: @source_conf["bucket"], key: obj.key)
        target_client.put_object(
          bucket: @target_conf["bucket"],
          key: target_key,
          body: get_resp.body,
          content_length: obj.size,
        )

        total_bytes += obj.size
        total_objects += 1
      end

      break unless page.is_truncated
      continuation_token = page.next_continuation_token
    end

    File.write(@stats_file, JSON.generate(
      "total_bytes" => total_bytes,
      "total_objects" => total_objects,
    ))
  end

  def self.build_client(conf)
    Aws::S3::Client.new(
      access_key_id: conf["access_key_id"],
      secret_access_key: conf["secret_access_key"],
      endpoint: conf["endpoint"],
      region: conf["region"],
      force_path_style: true,
      http_open_timeout: 5,
      http_read_timeout: 60,
      retry_limit: 3,
    )
  end
end
