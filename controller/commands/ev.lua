require"splay.base"
out = require"splay.out"
--events.l_o.level = 1


function t()
	l_o:warn("hello", "world")
	--error("kill")
end

events.loop(function()
	l_o = log.new(2, "[mylog]")
	l_o.write = function(level, ...)
		return log.global_write(
				level, coroutine.running(), string.format("%.4f", misc.time()), ...)
	end
	--l_o.out = out.network("localhost", 20000)
	while events.sleep(1) do
		events.thread(t)
	end
end)
