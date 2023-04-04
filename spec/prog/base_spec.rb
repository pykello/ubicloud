# frozen_string_literal: true

require_relative "../model/spec_helper"

RSpec.describe Prog::Base do
  it "deletes a child with a exitval set" do
    parent = Strand.create(prog: "Test", label: "reaper")
    parent.add_child(exitval: "{}", parent_id: parent.id,
      prog: "Test", label: "start")
    expect {
      parent.run
    }.to change { parent.load.leaf? }.from(false).to(true)
  end

  it "does not delete a child that has no retval yet" do
    parent = Strand.create(prog: "Test", label: "reaper")
    parent.add_child(parent_id: parent.id, prog: "Test", label: "start")

    expect {
      parent.run
    }.not_to change { parent.load.leaf? }.from(false)
  end

  it "can push prog and frames on the stack" do
    st = Strand.create(prog: "Test", label: :pusher1)
    expect {
      st.run
    }.to change { st.label }.from("pusher1").to("pusher2")
    expect(st.retval).to be_nil

    expect {
      st.run
    }.to change { st.label }.from("pusher2").to "pusher3"
    expect(st.retval).to be_nil

    expect {
      st.run
    }.to change { st.label }.from("pusher3").to "pusher2"
    expect(st.retval).to eq Sequel.pg_jsonb_wrap(3)

    expect {
      st.run
    }.to change { st.label }.from("pusher2").to "pusher1"
    expect(st.retval).to eq Sequel.pg_jsonb_wrap(2)

    st.run
    expect(st.exitval).to eq Sequel.pg_jsonb_wrap(1)

    expect { st.run }.to raise_error "already deleted"
    expect { st.reload }.to raise_error Sequel::NoExistingObject
  end
end