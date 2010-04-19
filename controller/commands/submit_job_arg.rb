#!/usr/bin/env ruby

# Splay Controller
# Copyright 2006 - 2008 Lorenzo Leonini (University of Neuchâtel)
# http://www.splay-project.org

# This file is part of Splay Controller.
#
# Splay Controller is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# Splay Controller is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# Splay Controller.  If not, see <http://www.gnu.org/licenses/>.


require '../lib/common'

$log.level = Logger::INFO
	
if ARGV.size < 1
	puts("arguments: <lua_file> [<lua_args>*]")
	exit
end

# Lua file
file = ARGV[0]

puts "Reading file: #{file}\n"

lines = File.readlines(file)

options = parse_ressources(lines)
code = only_code(lines)

code = command_line_to_code(file, 1) + code

puts code
exit

ref = OpenSSL::Digest::MD5.hexdigest(rand(1000000).to_s)

$db.do "INSERT INTO jobs SET
		ref='#{ref}'
		#{to_sql(options)}
		, code='#{addslashes(code)}'"

job = $db.select_one "SELECT * FROM jobs WHERE ref='#{ref}'"

puts "Task transmitted to the controller: #{job['id']} (#{ref})"
puts
if options.size != 0 then puts(to_human(options)) end

watch(job)
