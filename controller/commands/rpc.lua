require"splay.base"

function call(a)
	log:print(a)
end


events.loop(function()
	log:print("sleeping 5")
	rpc = require"splay.rpc"
	events.sleep(5)
	rpc.server(job.me)
	while events.sleep(1) do
		rpc.call(job.me, {"call", "hello"})
	end
end)
