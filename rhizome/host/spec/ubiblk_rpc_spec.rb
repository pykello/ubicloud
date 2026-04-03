# frozen_string_literal: true

require_relative "../lib/ubiblk_rpc"

RSpec.describe UbiblkRpc do
  subject(:rpc) {
    described_class.new("/path/to/rpc.sock", 5, 100)
  }

  describe "#stats" do
    it "sends the stats command" do
      expect(rpc).to receive(:call).with("stats").and_return({
        "stats" => {"queues" => [{"bytes_read" => 100, "bytes_written" => 200, "read_ops" => 10, "write_ops" => 20}]},
      })
      result = rpc.stats
      expect(result["stats"]["queues"].first["bytes_read"]).to eq(100)
    end
  end

  describe "#call" do
    let(:unix_socket) { instance_double(UNIXSocket) }

    before do
      allow(UNIXSocket).to receive(:new).and_return(unix_socket)
    end

    it "sends a command and returns parsed response" do
      expect(unix_socket).to receive(:write_nonblock)
      expect(rpc).to receive(:read_response).with(unix_socket).and_return('{"stats": {"queues": []}}')
      expect(unix_socket).to receive(:close)
      expect(rpc.call("stats")).to eq({"stats" => {"queues" => []}})
    end
  end

  describe "#read_response" do
    let(:unix_socket) { instance_double(UNIXSocket) }

    it "can read a valid response" do
      response = {stats: {queues: []}}.to_json
      expect(IO).to receive(:select).and_return(1)
      expect(unix_socket).to receive(:read_nonblock).and_return(response)
      expect(rpc.read_response(unix_socket)).to eq(response)
    end

    it "throws a timeout exception if select returns nil" do
      expect(IO).to receive(:select).and_return(nil)
      expect(unix_socket).to receive(:close)
      expect { rpc.read_response(unix_socket) }.to raise_error(RuntimeError, "The request timed out after 5 seconds.")
    end

    it "throws an exception if response exceeds the limit" do
      expect(IO).to receive(:select).and_return(1)
      expect(unix_socket).to receive(:read_nonblock).and_return("a" * 200)
      expect { rpc.read_response(unix_socket) }.to raise_error(RuntimeError, "Response size limit exceeded.")
    end

    it "can read a multi-part valid response" do
      response = {stats: {queues: []}}.to_json
      expect(IO).to receive(:select).and_return(1, 1)
      expect(unix_socket).to receive(:read_nonblock).and_invoke(
        ->(_) { response[..5] },
        ->(_) { raise IO::EAGAINWaitReadable },
        ->(_) { response[6..] },
      )
      expect(rpc.read_response(unix_socket)).to eq(response)
    end
  end
end
