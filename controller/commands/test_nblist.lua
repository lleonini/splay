#!/blabla/lua this line must be auto-removed

--[[
BEGIN SPLAY RESSOURCES RESERVATION

nb_splayds 4
nb_list 2
bits 32

END SPLAY RESSOURCES RESERVATION
--]]

require"splay.base"

function base()

	print("> Job list")

	print("My position is: "..job.network.list.position)
	print("> All jobs list:")
	for pos, sl in pairs(job.network.list.nodes) do
		print("Slave "..pos.." ip: "..sl.ip.." ("..sl.start_port.."-"..sl.end_port..")")
	end
end

events.thread(base)
events.loop()


