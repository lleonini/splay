--[[
	Splayd
	Copyright 2006 - 2009 Lorenzo Leonini (University of Neuchâtel)
	http://www.splay-project.org
]]

--[[
This file is part of Splayd.

Splayd is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

Splayd is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
Splayd.  If not, see <http://www.gnu.org/licenses/>.
]]

--[[
Collection of output functions for splay.log. It's not recommended when
debugging some modules to use an output that can recursivly generates events
in that module (ie: if you want to debug a network or events problem, do
not use network output).
]]

local io = require"io"
local socket = require"splay.socket"

local ori_print = print
local tostring = tostring
local type = type

module("splay.out")

_COPYRIGHT   = "Copyright 2006 - 2009 Lorenzo Leonini (University of Neuchâtel)"
_DESCRIPTION = "Outs for log system"
_VERSION     = 0.5

function print()
	return function(msg)
		ori_print(tostring(msg))
		io.flush()
	end
end

function file(file)
	if file then
		local f, err = io.open(file, "a+")
		if f then
			return function(msg)
				f:write(tostring(msg).."\n")
				f:flush()
				return true
			end
		else
			return nil, err
		end
	else
		return nil, "no file"
	end
end

function network(ip, port)
	if type(ip) == "table" and ip.ip and ip.port then
		port = ip.port
		ip = ip.ip
	end
	if ip and port then
		local s, err = socket.connect(ip, port)
		if s then
			return function(msg)
				s:send(tostring(msg).."\n")
				return true
			end
		else
			return nil, err
		end
	else
		return nil, "no ip and port"
	end
end
