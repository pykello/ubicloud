# frozen_string_literal: true

require_relative "../lib/kek_pipe"
require "tmpdir"

RSpec.describe KekPipe do
  describe ".run_with_kek_pipe" do
    it "passes kek via pipe; with stdin" do
      Dir.mktmpdir do |dir|
        output_file = File.join(dir, "output-with-stdin")
        kek_pipe = File.join(dir, "kek.pipe")
        script = <<~RUBY
          kek = File.read(ARGV[0])
          stdin = STDIN.read
          File.write(ARGV[1], [ENV.fetch("TEST_KEK_ENV"), kek, stdin].join("|"))
        RUBY

        described_class.run_with_kek_pipe(
          ["ruby", "-e", script, kek_pipe, output_file],
          kek_pipe: kek_pipe,
          kek_content: "kek-content-with-stdin",
          stdin: "stdin-payload",
          env: {"TEST_KEK_ENV" => "env-with-stdin"}
        )

        expect(File.read(output_file)).to eq("env-with-stdin|kek-content-with-stdin|stdin-payload")
      end
    end

    it "passes kek via pipe; without stdin" do
      Dir.mktmpdir do |dir|
        output_file = File.join(dir, "output-without-stdin")
        kek_pipe = File.join(dir, "kek.pipe")
        script = <<~RUBY
          kek = File.read(ARGV[0])
          File.write(ARGV[1], [ENV.fetch("TEST_KEK_ENV"), kek].join("|"))
        RUBY

        described_class.run_with_kek_pipe(
          ["ruby", "-e", script, kek_pipe, output_file],
          kek_pipe: kek_pipe,
          kek_content: "kek-content-without-stdin",
          env: {"TEST_KEK_ENV" => "env-without-stdin"}
        )

        expect(File.read(output_file)).to eq("env-without-stdin|kek-content-without-stdin")
      end
    end

    it "raises error if writing to kek pipe times out" do
      Dir.mktmpdir do |dir|
        kek_pipe = File.join(dir, "kek.pipe")
        script = <<~RUBY
          sleep 10
        RUBY

        expect {
          described_class.run_with_kek_pipe(
            ["ruby", "-e", script],
            kek_pipe: kek_pipe,
            kek_content: "kek-content",
            kek_write_timeout_sec: 0.1
          )
        }.to raise_error RuntimeError, "error writing KEK to pipe: execution expired"
      end
    end
  end
end
