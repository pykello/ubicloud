# frozen_string_literal: true

require_relative "unix_socket_rpc"

class UbiblkRpc
  include UnixSocketRpc

  def initialize(socket_path, timeout = 5, response_size_limit = 1048576)
    @socket_path = socket_path
    @timeout = timeout
    @response_size_limit = response_size_limit
  end

  def stats
    call("stats")
  end

  def call(command)
    send_request({command: command})
  end
end
