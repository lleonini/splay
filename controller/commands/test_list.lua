#!/blabla/lua this line must be auto-removed

--[[
BEGIN SPLAY RESSOURCES RESERVATION

list_size 8
list_type RANDOM

END SPLAY RESSOURCES RESERVATION
--]]
--list_type rand
--list_size 1


require"splay.base"

function base()
	print("> job list:")
	if job then
		if job.position then
			print("OK: my position is: "..job.position)
		else
			print("no position")
		end
		print("> me: "..job.me.ip..":"..job.me.port)
		print("> list type: "..job.list_type.." (size: "..#job.nodes..")")
		print("> All jobs list:")
		for pos, sl in pairs(job.nodes) do
			print("", pos.." ip: "..sl.ip..":"..sl.port)
		end
	else
		print "ERROR: No job list."
	end
end

events.thread(base)
events.loop()


