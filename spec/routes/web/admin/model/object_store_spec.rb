# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe CloverAdmin, "ObjectStore" do
  include AdminModelSpecHelper

  before do
    @instance = create_object_store
    admin_account_setup_and_login
  end

  it "displays the ObjectStore instance page correctly" do
    click_link "ObjectStore"
    expect(page.status_code).to eq 200
    expect(page.title).to eq "Ubicloud Admin - ObjectStore"

    click_link @instance.admin_label
    expect(page.status_code).to eq 200
    expect(page.title).to eq "Ubicloud Admin - ObjectStore #{@instance.ubid}"
  end
end
