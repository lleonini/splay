#!/blabla/lua this line must be auto-removed

--[[
BEGIN SPLAY RESSOURCES RESERVATION

END SPLAY RESSOURCES RESERVATION
--]]

require"splay.base"

events.loop(function()

	print("START")
	print("> Job list")

	print("My position is: "..job.network.list.position)
	print("> All jobs list:")
	for pos, sl in pairs(job.network.list.nodes) do
		print("Slave "..pos.." ip: "..sl.ip.." ("..sl.port..")")
	end

	i = 0
	while true do
		log:print("tic "..tostring(i))
		--print("tic "..tostring(i))
		events.sleep(1)
		i = i + 1
	end
end)
