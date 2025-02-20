# frozen_string_literal: true

require_relative "../model"

class Project < Sequel::Model
  one_to_many :access_tags
  one_to_many :access_policies
  one_to_one :billing_info, key: :id, primary_key: :billing_info_id
  one_to_many :github_installations

  many_to_many :vms, join_table: AccessTag.table_name, left_key: :project_id, right_key: :hyper_tag_id
  many_to_many :minio_clusters, join_table: AccessTag.table_name, left_key: :project_id, right_key: :hyper_tag_id
  many_to_many :private_subnets, join_table: AccessTag.table_name, left_key: :project_id, right_key: :hyper_tag_id
  many_to_many :postgres_resources, join_table: AccessTag.table_name, left_key: :project_id, right_key: :hyper_tag_id

  one_to_many :invoices, order: Sequel.desc(:created_at)

  dataset_module Authorization::Dataset

  plugin :association_dependencies, access_tags: :destroy, access_policies: :destroy, billing_info: :destroy

  include ResourceMethods
  include Authorization::HyperTagMethods

  def hyper_tag_name(project = nil)
    "project/#{ubid}"
  end

  include Authorization::TaggableMethods

  def user_ids
    access_tags_dataset.where(hyper_tag_table: Account.table_name.to_s).select_map(:hyper_tag_id)
  end

  def has_valid_payment_method?
    return true unless Config.stripe_secret_key
    !!billing_info&.payment_methods&.any?
  end

  def path
    "/project/#{ubid}"
  end

  def current_invoice
    begin_time = invoices.first&.end_time || Time.new(Time.now.year, Time.now.month, 1)
    end_time = Time.now

    if (invoice = InvoiceGenerator.new(begin_time, end_time, project_id: id).run.first)
      return invoice
    end

    content = {
      "resources" => [],
      "subtotal" => 0.0,
      "credit" => 0.0,
      "discount" => 0.0,
      "cost" => 0.0
    }

    Invoice.new(project_id: id, content: content, begin_time: begin_time, end_time: end_time, created_at: Time.now, status: "current")
  end

  def self.feature_flag(*flags)
    flags.map(&:to_s).each do |flag|
      define_method "set_#{flag}" do |value|
        update(feature_flags: feature_flags.merge({flag => value}))
      end

      define_method "get_#{flag}" do
        feature_flags[flag]
      end
    end
  end

  feature_flag :enable_postgres
end
