# frozen_string_literal: true

require_relative "../../common/lib/util"

require "fileutils"
require "timeout"

module KekPipe
  WRITE_TIMEOUT_SEC = 5

  def self.with_kek_pipe(kek_pipe, owner: nil)
    rm_if_exists(kek_pipe)
    File.mkfifo(kek_pipe, 0o600)
    FileUtils.chown owner, owner, kek_pipe if owner
    yield kek_pipe
  ensure
    FileUtils.rm_f(kek_pipe)
  end

  def self.write_kek_to_pipe(kek_pipe, payload, timeout_sec: WRITE_TIMEOUT_SEC)
    Timeout.timeout(timeout_sec) do
      File.open(kek_pipe, File::WRONLY) do |file|
        file.write(payload)
      end
    end
  end

  def self.run_with_kek_pipe(command, kek_pipe:, kek_content:, stdin: nil, env: {}, owner: nil, kek_write_timeout_sec: WRITE_TIMEOUT_SEC)
    with_kek_pipe(kek_pipe, owner: owner) do |pipe|
      spawn_opts = {}
      stdin_r = nil
      stdin_writer = nil

      if stdin
        stdin_r, stdin_w = IO.pipe
        spawn_opts[:in] = stdin_r

        stdin_writer = Thread.new do
          stdin_w.write(stdin)
        ensure
          stdin_w.close
        end
      end

      pid = Process.spawn(env, *command, **spawn_opts)
      stdin_r&.close

      begin
        write_kek_to_pipe(pipe, kek_content, timeout_sec: kek_write_timeout_sec)
      rescue => e
        begin
          Process.kill("TERM", pid)
        rescue Errno::ESRCH
          # Child has already exited.
        end
        Process.waitpid(pid)
        stdin_writer&.join
        raise "error writing KEK to pipe: #{e.message}"
      end

      _, status = Process.wait2(pid)
      stdin_writer&.join

      fail CommandFail.new("command failed: #{command.join(" ")}", "", "") unless status.success?
    end
  end
end
