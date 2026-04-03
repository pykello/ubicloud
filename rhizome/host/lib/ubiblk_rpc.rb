# frozen_string_literal: true

require "json"
require "socket"

class UbiblkRpc
  def initialize(socket_path, timeout = 5, response_size_limit = 1048576)
    @socket_path = socket_path
    @timeout = timeout
    @response_size_limit = response_size_limit
  end

  def stats
    call("stats")
  end

  def call(command)
    payload = {command: command}

    unix_socket = UNIXSocket.new(@socket_path)
    unix_socket.write_nonblock(payload.to_json + "\n")

    response = JSON.parse(read_response(unix_socket))
    unix_socket.close

    response
  end

  def read_response(socket)
    buffer = +""
    start_time = Time.now

    begin
      elapsed_time = Time.now - start_time
      ready_sockets = IO.select([socket], nil, nil, @timeout - elapsed_time)

      unless ready_sockets
        socket.close
        raise "The request timed out after #{@timeout} seconds."
      end

      loop do
        buffer << socket.read_nonblock(4096)
        break if valid_json?(buffer)
        raise "Response size limit exceeded." if buffer.length > @response_size_limit
      end
    rescue IO::WaitReadable
      retry
    end

    buffer
  end

  private

  def valid_json?(json_str)
    JSON.parse(json_str)
    true
  rescue JSON::ParserError
    false
  end
end
