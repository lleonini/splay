-- Tests Copas with a simple Echo server
--
-- Run the test file and the connect to the server by telnet on the used port
-- to stop the test just send the command "quit"

require"splay.base"
net = require"splay.net"

port = job.me.port

local function echoHandler(s)
	print("server")
  while true do
    local data = s:receive("*l")
    if not data or data == "quit" then
      break
    end
		s:send(data.."\n")
  end
end

net.server(echoHandler, port)
events.loop()
