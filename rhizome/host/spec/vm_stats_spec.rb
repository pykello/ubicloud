# frozen_string_literal: true

require_relative "../lib/vm_stats"
require_relative "../lib/ubiblk_rpc"

RSpec.describe VmStats do
  let(:vm_stats) { described_class.new("vmh6b1sz") }

  before do
    allow(vm_stats).to receive(:r).with("getconf", "CLK_TCK").and_return("100\n")
  end

  def stub_unit_property(unit, property, value)
    allow(vm_stats).to receive(:r)
      .with("systemctl", "show", unit, "--property", property)
      .and_return("#{property}=#{value}\n")
  end

  describe "#collect" do
    it "collects stats for the VM and its disks" do
      stub_unit_property("vmh6b1sz", "MainPID", "3373")
      stub_unit_property("vmh6b1sz", "ActiveEnterTimestampMonotonic", "31554196")
      stub_unit_property("vmh6b1sz-0-storage", "MainPID", "3350")
      stub_unit_property("vmh6b1sz-0-storage", "MemoryPeak", "51892224")
      stub_unit_property("vmh6b1sz-0-storage", "MemorySwapPeak", "123879")
      stub_unit_property("vmh6b1sz-0-storage", "ActiveEnterTimestampMonotonic", "31534196")
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(1616.0)
      expect(File).to receive(:read).with("/proc/3373/stat").and_return("3373 (cloud-hyperviso) S 1 3373 3373 0 -1 4194560 1163 0 0 0 95143 16431 0 0 20 0 13 0 3364 8618754048 960 18446744073709551615 135770696667136 135770699811150 140729095742720 0 0 0 134234114 69632 1073759298 0 0 0 17 7 0 0 0 89566 0 135770700348320 135770700898816 93826017284096 140729095744653 140729095745099 140729095745099 140729095745483 0")
      expect(File).to receive(:read).with("/proc/3350/stat").and_return("3350 (vhost-backend) S 1 3350 3350 0 -1 4194560 15183 45 31 0 16602 733 0 0 20 0 7 0 3351 17248038912 10371 18446744073709551615 140535920156672 140535933113610 140725366025408 0 0 0 0 4096 1088 0 0 0 17 7 0 0 0 0 0 140535936046520 140535939797664 93825003057152 140725366033855 140725366033953 140725366033953 140725366034378 0")
      expect(File).to receive(:foreach).with("/proc/3350/io")
        .and_yield("rchar: 872010\n")
        .and_yield("wchar: 1174987\n")
        .and_yield("syscr: 34992\n")
        .and_yield("syscw: 146630\n")
        .and_yield("read_bytes: 1185382400\n")
        .and_yield("write_bytes: 5457008640\n")
        .and_yield("cancelled_write_bytes: 0\n")

      expect(File).to receive(:read).with("/vm/vmh6b1sz/prep.json").and_return(JSON.generate(
        {
          "max_vcpus" => 8,
          "storage_volumes" => [
            {
              "boot" => true,
              "image" => "ubuntu-noble",
              "image_version" => "20250502.1",
              "encrypted" => true,
              "disk_index" => 0,
              "vhost_block_backend_version" => "v0.4.0",
              "num_queues" => 4,
              "queue_size" => 64,
              "size_gib" => 20,
              "storage_device" => "DEFAULT",
            },
            {
              "disk_index" => 1,
              "encrypted" => true,
            },
          ],
        },
      ))

      rpc_response = {
        "stats" => {
          "queues" => [
            {"bytes_read" => 500000, "bytes_written" => 300000, "read_ops" => 100, "write_ops" => 50},
            {"bytes_read" => 400000, "bytes_written" => 200000, "read_ops" => 80, "write_ops" => 40},
            {"bytes_read" => 300000, "bytes_written" => 100000, "read_ops" => 60, "write_ops" => 30},
            {"bytes_read" => 200000, "bytes_written" => 50000, "read_ops" => 40, "write_ops" => 20},
          ],
        },
      }
      rpc_socket_path = "/var/storage/vmh6b1sz/0/rpc.sock"
      expect(File).to receive(:exist?).with(rpc_socket_path).and_return(true)
      ubiblk_rpc = instance_double(UbiblkRpc)
      expect(UbiblkRpc).to receive(:new).with(rpc_socket_path).and_return(ubiblk_rpc)
      expect(ubiblk_rpc).to receive(:stats).and_return(rpc_response)

      expect(vm_stats.collect).to eq(
        {
          "vm" => {
            "main_pid" => "3373",
            "vcpus" => 8,
            "active_age_ms" => 1584446,
            "cpu_stats" => {
              "user_time_ms" => 951430,
              "system_time_ms" => 164310,
              "total_time_ms" => 1115740,
            },
          },
          "disk_0" => {
            "main_pid" => "3350",
            "memory_peak_bytes" => 51892224,
            "memory_swap_peak_bytes" => 123879,
            "vhost_block_backend_version" => "v0.4.0",
            "num_queues" => 4,
            "queue_size" => 64,
            "size_gib" => 20,
            "active_age_ms" => 1584466,
            "cpu_stats" => {
              "user_time_ms" => 166020,
              "system_time_ms" => 7330,
              "total_time_ms" => 173350,
            },
            "io_stats" => {
              "read_bytes" => 1185382400,
              "write_bytes" => 5457008640,
            },
            "rpc_stats" => {
              "read_bytes" => 1400000,
              "write_bytes" => 650000,
              "read_ops" => 280,
              "write_ops" => 140,
            },
          },
        },
      )
    end
  end

  describe "#unit_property" do
    it "returns the value of the specified property for the given systemd unit" do
      stub_unit_property("my-unit", "MainPID", "1234")
      expect(vm_stats.unit_property("my-unit", "MainPID")).to eq("1234")
    end

    it "raises an error if the property is not found" do
      expect(vm_stats).to receive(:r).with("systemctl", "show", "my-unit", "--property", "MainPID").and_return("\n")
      expect { vm_stats.unit_property("my-unit", "MainPID") }.to raise_error(RuntimeError, "unexpected output from systemctl show: \"\"")
    end
  end

  describe "#cpu_stats" do
    it "returns the user, system, and total CPU time in milliseconds for the given PID" do
      stat_content = "3162 (vhost-backend) S 1 3162 3162 0 -1 4194560 9766 45 10 0 10478 491 0 0 20 0 4 0 3174 68799508480 7680 18446744073709551615 130089075412992 130089077621693 140721008361056 0 0 0 0 4096 1088 0 0 0 17 55 0 0 0 0 0 130089077837464 130089078048960 93825782800384 140721008364963 140721008365100 140721008365100 140721008365514 0"
      expect(File).to receive(:read).with("/proc/1234/stat").and_return(stat_content)
      expect(vm_stats.cpu_stats("1234")).to eq({"user_time_ms" => 104780, "system_time_ms" => 4910, "total_time_ms" => 109690})
    end

    it "works even if comm has a name with spaces and parentheses" do
      stat_content = "2386855 (weird (name) ) ) S 2385257 2386855 2385257 34818 2386856 4194304 157 0 0 0 192 321 0 0 20 0 1 0 23386827 5820416 384 18446744073709551615 109656114941952 109656114955953 140720420466848 0 0 0 0 0 0 1 0 0 17 40 0 0 0 0 0 109656114965456 109656114966680 109656563896320 140720420468187 140720420468214 140720420468214 140720420470754 0"
      expect(File).to receive(:read).with("/proc/1234/stat").and_return(stat_content)
      expect(vm_stats.cpu_stats("1234")).to eq({"user_time_ms" => 1920, "system_time_ms" => 3210, "total_time_ms" => 5130})
    end
  end

  describe "#clk_tick" do
    it "returns the number of clock ticks per second" do
      expect(vm_stats).to receive(:r).with("getconf", "CLK_TCK").and_return("234\n")
      expect(vm_stats.clk_tick).to eq(234)
    end
  end

  describe "#ubiblk_disks" do
    it "returns the list of disk hashes for ubiblk disks" do
      expect(File).to receive(:read).with("/vm/vmh6b1sz/prep.json").and_return(
        JSON.generate({
          "storage_volumes" => [
            {"disk_index" => 0, "vhost_block_backend_version" => "v0.1", "queue_size" => 64, "num_queues" => 4, "size_gib" => 20, "storage_device" => "DEFAULT"},
            {"disk_index" => 1},
            {"disk_index" => 2, "vhost_block_backend_version" => "v0.1", "queue_size" => 128, "num_queues" => 2, "size_gib" => 40, "storage_device" => "nvme0"},
          ],
        }),
      )
      expect(vm_stats.ubiblk_disks).to eq([
        {"disk_index" => 0, "vhost_block_backend_version" => "v0.1", "queue_size" => 64, "num_queues" => 4, "size_gib" => 20, "storage_device" => "DEFAULT"},
        {"disk_index" => 2, "vhost_block_backend_version" => "v0.1", "queue_size" => 128, "num_queues" => 2, "size_gib" => 40, "storage_device" => "nvme0"},
      ])
    end
  end

  describe "#rpc_stats" do
    it "returns nil when the rpc socket does not exist" do
      expect(File).to receive(:exist?).with("/var/storage/vmh6b1sz/0/rpc.sock").and_return(false)
      expect(vm_stats.rpc_stats("DEFAULT", 0)).to be_nil
    end

    it "returns nil when the rpc call fails" do
      expect(File).to receive(:exist?).with("/var/storage/vmh6b1sz/0/rpc.sock").and_return(true)
      ubiblk_rpc = instance_double(UbiblkRpc)
      expect(UbiblkRpc).to receive(:new).with("/var/storage/vmh6b1sz/0/rpc.sock").and_return(ubiblk_rpc)
      expect(ubiblk_rpc).to receive(:stats).and_raise(Errno::ECONNREFUSED)
      expect(vm_stats.rpc_stats("DEFAULT", 0)).to be_nil
    end

    it "returns totals summed across all queues" do
      expect(File).to receive(:exist?).with("/var/storage/devices/nvme0/vmh6b1sz/1/rpc.sock").and_return(true)
      ubiblk_rpc = instance_double(UbiblkRpc)
      expect(UbiblkRpc).to receive(:new).with("/var/storage/devices/nvme0/vmh6b1sz/1/rpc.sock").and_return(ubiblk_rpc)
      expect(ubiblk_rpc).to receive(:stats).and_return({
        "stats" => {
          "queues" => [
            {"bytes_read" => 1000, "bytes_written" => 2000, "read_ops" => 10, "write_ops" => 20},
            {"bytes_read" => 3000, "bytes_written" => 4000, "read_ops" => 30, "write_ops" => 40},
          ],
        },
      })
      expect(vm_stats.rpc_stats("nvme0", 1)).to eq({
        "read_bytes" => 4000,
        "write_bytes" => 6000,
        "read_ops" => 40,
        "write_ops" => 60,
      })
    end

    it "uses DEFAULT_STORAGE_DEVICE when storage_device is nil" do
      expect(File).to receive(:exist?).with("/var/storage/vmh6b1sz/0/rpc.sock").and_return(false)
      expect(vm_stats.rpc_stats(nil, 0)).to be_nil
    end
  end
end
