--[[
BEGIN SPLAY RESSOURCES RESERVATION

network_nb_ports 2

END SPLAY RESSOURCES RESERVATION
--]]


require"splay.base"
net = require"splay.net"

port = job.me.port
port2 = port + 1

function server(s)
	--print("server", s)
	local data, err = s:receive("*l")
	if not data then print(err) end
	s:send(data.."\n")
	--error("hello")
end

function server2(s)
	s:send("aaaaa")
	events.sleep(10)
	s:send("aaaaa")
end

function handler(s)
	-- we check that we use copcall
	local ok = pcall(function() server(s) end)
	if ok then
		print("OK")
	else
		print("ERROR")
	end
end

p0 = socket.protect(function()
    local c = socket.try(socket.connect("localhost", port))
    local try = socket.newtry(function() c:close() end)
    try(c:send("hello\n"))
    local d = try(c:receive("*l"))
    c:close()
		return d
end)

p1 = socket.protect(function()
    local c = socket.try(socket.connect("non_existing", 80))
end)

p2 = socket.protect(function()
    local c = socket.try(socket.connect("localhost", port2))
		c:settimeout(0.1)
    local try = socket.newtry(function() c:close() end)
    try(c:receive(10))
    c:close()
end)

net.server(handler, port)
net.server(server2, port2)
events.loop(function()
	events.sleep(0.1)
	if p0() == "hello" then
		print("OK")
	else
		print("ERROR")
	end

	local ok, err = p1()
	if not ok then
		print("OK")
	else
		print("ERROR")
	end

	local ok, err = p2()
	if not ok then
		print("OK")
	else
		print("ERROR")
	end

	local c = socket.connect("localhost", port2)
	c:settimeout(0.1)
	local ok, err, part = c:receive(10)
	if not ok and part == "aaaaa" then
		print("OK")
	else
		print("ERROR")
	end
	os.exit()
end)
