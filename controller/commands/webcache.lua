--[[
	SPLAY Web Cache (on Pastry DHT)
	Copyright (C) 2008 Lorenzo Leonini - University of Neuchâtel
	http://www.splay-project.org
--]]

--[[ BEGIN SPLAY RESSOURCES RESERVATION

network_max_sockets 64
network_nb_ports 2

END SPLAY RESSOURCES RESERVATION ]]

require"splay.base"
rpc = require"splay.rpc"
crypto = require"crypto"
evp, thread, call, time = crypto.evp, events.thread, rpc.call, misc.time

--log.init({ip = "127.0.0.1", port = 10002, max_size = 1000000})
log.set_level(2)

tr, ti, sub = table.remove, table.insert, string.sub

----------[[ PASTRY ]]----------

-- Implementation parameters
-- key length 2^bits (max 160 because using SHA and divisible by 4)
b, leaf_size, bits = 4, 16, 128 -- default 4, 16, 128

-- R: routing table, L[i,s]: inferior and superior leaf set
-- Li sorted from greater to lower, Ls sorted from lower to greater
R, Li, Ls = {}, {}, {}

g_timeout, activity_time, check_time, ping_refresh = 60, 5, 10, 125
-- planetlab
--g_timeout, activity_time, check_time, ping_refresh = 60, 25, 20, 125

ping_c, actions, fails_count = {}, 0, 0
-- serialize insertion and reparation
insert_l, repair_l = events.new_lock(), events.new_lock()
-- protect leaf set
L_l, ping_c_l = events.new_lock(), events.new_lock()

key_size = math.log(math.pow(2, bits))/ math.log(math.pow(2, b))

if key_size < math.pow(2, b) then
	print("Key size must be greater or equal than base")
	os.exit()
end
if b ~= 4 then
	print("b must be 4, because base 16 (hexadecimal) is needed in one function.")
	os.exit()
end

-- initialize empty lines of an empty routing table
for i = 0, key_size - 1 do R[i] = {} end

function compute_id(o) return sub(evp.new("sha1"):digest(o), 1, bits / 4) end
function num(k) -- Hex dependant
	if k.id then return tonumber("0x"..k.id) else return tonumber("0x"..k) end
end 
function diff(key1, key2) return math.abs(num(key1) - num(key2)) end

-- return the length of the shared prefix
function shl(a, b)
	for i = 1, key_size do
		if sub(a, i, i) ~= sub(b, i, i) then return i - 1 end
	end
	return key_size
end

function row_col(key)
	local row = shl(key, job.me.id)
	return row, num(sub(key, row + 1, row + 1))
end

-- calculate our distance from a node
-- in this implementation distance = ping time
function ping(n, no_c)
	ping_c_l:lock()
	if not (not no_c and ping_c[n.id] and ping_c[n.id].last > time() - ping_refresh) then
		log.debug("ping "..n.id)
		local t = time()
		if rpc.ping(n, g_timeout) then
			ping_c[n.id] = {last = time(), value = true, time = time() - t}
		else
			ping_c[n.id] = {last = time(), value = false, time = math.huge}
			failed(n)
		end
	end
	local v, t = ping_c[n.id].value, ping_c[n.id].time
	ping_c_l:unlock()
	return v, t
end

-- Function called in insert_route() only, ping IS always cached.
function distance(n)
	log.debug("distance "..n.id)
	local v, t = ping(n)
	return t
end

function already_in(node)
	-- we could check that a node in the leafset could eventually goes in the
	-- routing table later, but not useful at the routing level
	if node.id == job.me.id then return true end
	for _, n in pairs(leafs()) do
		if n.id == node.id then return true end
	end
	for r = 0, key_size - 1 do
		for c = 0, key_size - 1 do
			if R[r][c] and R[r][c].id == node.id then
				-- Found, but we need to be sure that this node
				-- cannot be reinserted as leaf (while nodes die, some nodes only in
				-- routing table can later be elected for leafset)
				-- NOTE it's not effective to do like that, better to have a little
				-- daemon that fill leafset - routing table when there is an empty
				-- place.
				if range_leaf(node.id) then return false else return true end
			end
		end
	end
end

-- Entry point when we receive a new node
-- ok: to avoid notify a node that just notify us (and some pings too)
function insert(node, ok) thread(function() insert_t(node, ok) end) end
function insert_t(node, ok)
	insert_l:lock()
	if already_in(node) or (not ok and not ping(node)) then
		log.debug("do not insert "..node.id)
	else
		log.debug("insert "..node.id)
		-- normally these inserts will require NO network operations (except logs)
		local r1, r2 = insert_leaf(node), insert_route(node)
		if (r1 or r2) and not ok then
			thread(function()
				local r = call(node, {'notify', job.me}, g_timeout)
				if r then return true else failed(node) end
			end)
		end
	end
	insert_l:unlock()
end

function insert_route(node)
	log.debug("insert_route "..node.id)
	local row, col = row_col(node.id)
	local r = R[row][col]
	log.debug("   at pos "..row..":"..col)
	-- if the slot is empty, or there is another node that is more distant
	-- => we put the new node in the routing table
	if not r then
		log.debug("   empty => OK")
		R[row][col] = node
		return true
	else
		log.debug("   already "..r.id)
		if r.id ~= node.id and distance(node) < distance(r) then
			log.debug("   OK")
			R[row][col] = node
			return true
		else
			log.debug("   NOT OK")
			return false
		end
	end
end

function insert_leaf(node)
	L_l:lock()
	log.debug("insert_leaf "..node.id)
	local r1, r2 = iol(node, Li, false), iol(node, Ls, true)
	L_l:unlock()
	return r1 or r2
end

-- insert_one_leaf
function iol(node, leaf, sup)
	for i = 1, leaf_size / 2 do
		if leaf[i] then
			if node.id == leaf[i].id then break end
			if (not sup and misc.between_c(num(node), num(leaf[i]), num(job.me))) or
				(sup and misc.between_c(num(node), num(job.me), num(leaf[i]))) then
				ti(leaf, i, node)
				while #leaf > leaf_size / 2 do tr(leaf) end
				log.debug("    leaf inserted "..node.id.." at pos "..i)
				return i
			end
		else
			leaf[i] = node
			log.debug("    leaf inserted "..node.id.." at pos "..i)
			return i
		end
	end
	return false
end

-- leaf inf and sup mixed with each elements only once
function leafs()
	L_l:lock()
	local L = misc.dup(Li)
	for _, e in pairs(Ls) do
		local found = false
		for _, e2 in pairs(Li) do
			if e.id == e2.id then found = true break end
		end
		if not found then L[#L + 1] = e end
	end
	L_l:unlock()
	return L
end

function range_leaf(D) -- including ourself in the range
	local min, max = num(job.me), num(job.me) -- Way to put ourself in the range.
	L_l:lock()
	if #Li > 0 then min = num(Li[#Li]) end
	if #Ls > 0 then max = num(Ls[#Ls]) end
	L_l:unlock()
	return misc.between_c(num(D), min - 1, max + 1)
end

function nearest(D, nodes)
	log.debug("nearest "..D)
	local d, j = math.huge, nil
  for i, n in pairs(nodes) do
		if diff(D, n) < d then
			d = diff(D, n)
			j = i
		end
	end
	return nodes[j]
end

function repair(row, col, id)
	repair_l:lock()
	if not R[row][col] then -- already repaired...
		log.debug("repair "..row.." "..col)
		-- We only contact node that have the same prefix as us at least until the
		-- row of the failed node. That means if we ask this kind of node a
		-- replacement for the failed node at that position, it will give us a node
		-- that fit too in our routing table.
		local r = row
		while r <= key_size - 1 and not rfr(r, row, col, id) do r = r + 1 end
	end
	repair_l:unlock()
end

-- Use row 'r' to contact a node that could give us a replacement for the node
-- at pos (row; col)
-- id: to avoid re-inserting the same failed node
function rfr(r, row, col, id) -- repair from row
--	log.debug("rfr "..r.." "..row.." "..col.." "..id)
	for c, node in pairs(R[r]) do
		if c ~= col then
			local ok, r = rpc.a_call(node, {'get_node', row, col}, g_timeout)
			-- We verify that to no accept the same broken node than before.
			if ok then
				r = r[1]
				if r and r.id ~= id then
					-- We REALLY ping this node now
					if ping(r, true) then
						insert(r)
						log.info("Node repaired with "..r.id.." "..r.ip..":"..r.port)
						return true
					end
				end
			else
				failed(node)
			end
		end
	end
end

function failed(node) thread(function() failed_t(node) end) end
function failed_t(node)
	log.debug("failed "..node.id.." "..node.ip..":"..node.port)
	-- update cache
	ping_c_l:lock()
	ping_c[node.id] = {last = time(), value = false, time = math.huge}
	ping_c_l:unlock()
	-- clean leafs
	L_l:lock()
	for i, n in pairs(Li) do if node.id == n.id then tr(Li, i) end end
	for i, n in pairs(Ls) do if node.id == n.id then tr(Ls, i) end end
	L_l:unlock()
	local row, col = row_col(node.id)
	if R[row][col] and R[row][col].id == node.id then
		R[row][col] = nil
		repair(row, col, node.id)
	end
end

-- local, we want to join "node"
-- we have not its id, we can't add it !
function join(node)
	log.debug("join "..node.ip..":"..node.port)
	local r, err = call(node, {'route', {typ = "#join#"}, job.me.id})
	if not r then return nil, err end
	for _, e in pairs(r) do
		if e.id then
			log.debug("received node "..e.id.." "..e.ip..":"..e.port)
			insert(e)
		end
	end
	return true
end

function try_route(msg, key, T)
	log.debug("try_route "..key)
	local msg, T, reply = forward(msg, key, T)

	if not T then return reply end -- application choose to stop msg propagation
	log.debug("try_route routing "..key.." to host "..T.id.." "..T.ip..":"..T.port)
	local ok, n = rpc.a_call(T, {'route', msg, key}, g_timeout)
	if ok then
		if n[1] then
			if msg.typ == "#join#" then
				local row, col = row_col(key)
				for _, node in pairs(R[row]) do
					local found = false
					for _, j in pairs(n[1]) do
						if j.id == node.id then
							found = true
							break
						end
					end
					if not found then
						ti(n[1], node)
					end
				end
			end
			return unpack(n)
		else
			return nil
		end
	else 
		failed(T)
		log.info("cannot route through "..T.id)
		-- before, wa always reply somebody (us at the very end...)
		--return route(msg, key)
	end
end

function route(msg, key, no_count_action) -- Pastry API
	log.debug("route "..key.." "..tostring(msg.typ))
	if not no_count_action then actions = actions + 1 end

	-- good only if try_route halt on error...
	if msg.typ == "#test#" then
		if not msg.count then msg.count = 0 else msg.count = msg.count + 1 end
		if not msg.trace then msg.trace = "" end
		if not msg.hops then msg.hops = {job.me} else ti(msg.hops, job.me) end
	end

	if key ~= job.me.id then
		-- leo naive routing
		local T = nil -- target node
		local nodes = {job.me, unpack(leafs())}
		local row = row_col(key)
		for r = row, key_size - 1 do 
			for _, T in pairs(R[r]) do
				if T then ti(nodes, T) end
			end
		end
		T = nearest(key, nodes)
		if T.id ~= job.me.id then
			return try_route(msg, key, T)
		end
	end
	-- we are the best node for that key
	deliver(msg, key)
	
	if msg.typ == "#join#"
		then return {job.me, unpack(leafs())}
	else
		return job.me
	end
end

-- if no activity, create artificial one to detect route failures
function activity()
	log.debug("activity")
	if actions == 0 then
		local key = compute_id(math.random(1, 1000000000))
		log.debug("activity msg: "..key)
		thread(function() route({typ = "#activity#"}, key, true) end)
	end
	actions = 0
end

function do_leaf(node)
	local r = call(node, 'leafs', g_timeout)
	if r then
		log.debug("check receive "..#r.." leafs")
		for _, n in pairs(r) do insert(n) end
	else
		failed(node)
	end
end

function check_daemon()
	local pos = 1
	while events.sleep(check_time) do
		log.debug("check daemon")
		local L = leafs()
		if pos < #L then pos = pos + 1 else pos = 1 end
		-- case where leaf set is empty
		if L[pos] then do_leaf(L[pos]) end
	end
end

-- RPC aliases
function get_node(row, col) return R[row][col] end
function notify(node) insert(node, true) return true end

-- Pastry API
function send(msg, node) return call(node, {'route', msg, node.id}) end

-- Pastry API (must override)
function forward(msg, key, T) return msg, T end
function deliver(msg, key)
	if msg.typ == "#test#" and msg.origin then
		call(msg.origin, {'delivered', key, msg})
	end
	if msg.typ == "#webserver#" and msg.origin then
		call(msg.origin, {'webserver_found', key, msg})
	end
end

----------[[ WEBCACHE ]]----------

-- TODO
-- - do storage on files
-- - cache expiration
-- - we should implement a "manual" http client, because we need to be
-- sure that the size of the page/object is not too big (if not => memory
-- limit => kill of the job)

http = require"socket.http"
net = require"splay.net"

-- REQUIREMENTS
-- 2 sockets
-- good memory (6 Mo)
-- max number of files: 8192
-- max disk space: 128Mo
-- max file descriptors: 64

-- store in files
function cache_webserver(s)
	local cache_hit = true
	local first = s:receive("*l")

	-- url is in the form "/www.domain.com/page.html" without leading http:/
	local url = "http:/"..string.match(first, "GET ([^ ]*) ")
	local file_name = "cache_"..compute_id(url)
	log.print("SPLAYCache query: "..url)

	local f = io.open(file_name, "r")
	if not f then
		cache_hit = false
		local b, c, h = http.request(url)

		if b then
			f = io.open(file_name, "w")
			f:write(b)
			f:close()
		else
			log.print("Error getting: "..url)
		end
	end

	f = io.open(file_name, "r")
	if f then
		local page = ""
		if cache_hit then
			page = "<!-- SPLAYCache HIT -->\n"
			log.print("SPLAYCache HIT: "..url)
		else
			page = "<!-- SPLAYCache MISS -->\n"
			log.print("SPLAYCache MISS: "..url)
		end
		page = page..f:read("*a")

			s:send([[
HTTP/1.1 200 OK
Content-Type: text/html
Connection: close
Content-Length: ]]..string.len(page).."\n\n"..page)
	else
			s:send([[
HTTP/1.1 404 Not Found
Content-Type: text/html
Connection: close

]])
	end
end

web_cache = {}
function cache_webserver_mem(s)
	local cache_hit = true
	local first = s:receive("*l")

	-- url is in the form "/www.domain.com/page.html" without leading http:/
	local url = "http:/"..string.match(first, "GET ([^ ]*) ")
	log.print("SPLAYCache query: "..url)

	if not web_cache[url] then
		cache_hit = false
		local b, c, h = http.request(url)

		if b then
			web_cache[url] = b
		else
			log.print("Error getting: "..url)
		end
	end

	if web_cache[url] then
		local page = ""
		if cache_hit then
			page = "<!-- SPLAYCache HIT -->\n"
			log.print("SPLAYCache HIT: "..url)
		else
			page = "<!-- SPLAYCache MISS -->\n"
			log.print("SPLAYCache MISS: "..url)
		end
		page = page..web_cache[url]

			s:send([[
HTTP/1.1 200 OK
Content-Type: text/html
Connection: close
Content-Length: ]]..string.len(page).."\n\n"..page)
	else
			s:send([[
HTTP/1.1 404 Not Found
Content-Type: text/html
Connection: close

]])
	end
end

function redirect_webserver(s)
	local first = s:receive("*l")

	-- url is in the form "/www.domain.com/page.html" without leading http:/
	local url = string.match(first, "GET ([^ ]*) ")

	local dest = route({typ = "#webserver#"}, compute_id(url), true)

	local reply = ""

	-- TODO check url format
	if not dest then
		log.print("Redirect problem")

		local html = [[
<html>
<head>
<title>Service unavailable</title>
</head>
<body>
<h1>Service unavailable</h1>
</body>
</html>
]]

		reply = [[
HTTP/1.1 503 Service Unavailable
Content-Type: text/html
Connection: close
Content-Length: ]]..string.len(html).."\n\n"..html

	else
		log.print("Redirecting to "..dest.ip..":"..tostring(dest.port + 1))

		local dest_s = "http://"..dest.ip..":"..tostring(dest.port + 1)..url
print(dest_s)
		local html = [[
<html>
<head>
<title>Moved</title>
</head>
<body>
<h1>Moved</h1>
<p>This page has moved to <a href="]]..dest_s..[[">]]..dest_s..[[</a>.</p>
</body>
</html>
]]

		reply = [[
HTTP/1.1 307 Temporary redirect
Location: ]]..dest_s.."\n"..
[[
Content-Type: text/html
Connection: close
Content-Length: ]]..string.len(html).."\n\n"..html

	end
	s:send(reply)
end  

-------------------------- INSTRUMENTATION FUNCTIONS -----------------------

function display_route_table()
	local out = ""
	--for i = 0, key_size - 1 do
	for i = 0, key_size / 4 do
		local str = ""..i..": "
		for c = 0, math.pow(2, b) - 1 do
			if R[i][c] then
				str = str.." "..R[i][c].id
			else
				str = str.." -"
			end
		end
		out = out..str.."\n"
	end
	return out
end

function display_leaf()
	local out = ""
	for i = #Li, 1, -1 do
		if Li[i] then
			out = out.." "..Li[i].id
			--out = out.." "..Li[i].id.."("..num(Li[i])..")"
		end
	end
	out = out.." ["..job.me.id.."]"
	--out = out.." ["..job.me.id.."("..num(job.me)..")]"
	for i = 1, #Ls do
		if Ls[i] then
			out = out.." "..Ls[i].id
			--out = out.." "..Ls[i].id.."("..num(Ls[i])..")"
		end
	end
	return out
end

function socket_stats()
	if socket.stats then
		return socket.stats()
	end
end

function debug()
	if socket.infos then
		socket.infos()
	end
	if events.stats then
		print(events.stats())
	end

	log.print("_________________________________________")
	collectgarbage()
	log.print(gcinfo().." ko")
	log.print("ME: "..job.me.id)
	log.print(display_route_table())
	log.print(display_leaf())
	log.print("_________________________________________")
	print()
end

function shell_test(a)
	a = a or "no parameter"
	log.print(a)
	return "test ok: "..a
end

------------------------------------------------------------------

events.loop(function()

	local rdv = nil
	if not job then -- local or rdv
		if not arg[1] then
			print("some args missing")
			os.exit()
		end
		if arg[1] == "rdv" then -- rdv
			job = {me = {ip = arg[2], port = tonumber(arg[3])}}
		else
			job = {me = {ip = arg[1], port = tonumber(arg[2])}}
			rdv = {ip = "127.0.0.1", port = 20000}
		end
	else -- planetlab
		rdv = {ip = "192.42.43.42", port = 20000}
	end

	job.me.id = compute_id(math.random(1, 1000000000)..job.me.ip..tostring(job.me.port))

	if not rpc.server(job.me, 24) then
		log.error("RPC bind error: "..job.me.port)
		events.sleep(5)
		os.exit()
	end
	if not net.server(cache_webserver, job.me.port + 1) then
		log.error("Cache server bind error: ", job.me.port + 1)
		events.sleep(5)
		os.exit()
	end

	if not rdv then -- I'm the RDV
		log.print("RDV: "..job.me.ip..":"..job.me.port)
		if not net.server(redirect_webserver, 8080) then
			log.error("Redirect server bind error: 8080")
			events.sleep(5)
			os.exit()
		end
	else
		log.print("UP: "..job.me.ip..":"..job.me.port.." TRY JOINING "..rdv.ip..":"..rdv.port)

		-- wait for other nodes to come up
		events.sleep(10 + math.random(0, 50))

		-- try to join RDV
		local try = 0
		local ok, err = join(rdv)
		while not ok do
			try = try + 1
			if try <= 3 then
				log.print("Cannot join "..rdv.ip..":"..rdv.port..": "..tostring(err).." => try again")
				events.sleep(math.random(try * 30, try * 60))
				ok, err = join(rdv)
			else
				log.print("Cannot join "..rdv.ip..":"..rdv.port..": "..tostring(err).."  => end")
				events.sleep(5)
				os.exit()
			end
		end
	end

	log.print("START: "..job.me.id)
	events.periodic(activity, activity_time)
	events.periodic(debug, 30)
	thread(check_daemon)
end)
