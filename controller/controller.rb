#!/usr/bin/env ruby

#	Splay Controller
#
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


require 'lib/common'

# We force only one log daemon and one splayd daemon
Config::NumLogd = 1
Config::NumSplayd = 1

require 'lib/all'

#$log.level = Logger::DEBUG
$log.level = Logger::INFO

puts
puts ">>> Splayd Controller #{Config::CTLVersion} <<<"
puts
puts "http://www.splay-project.org"
puts "Splay Controller is licensed under GPL v3, see COPYING"
puts

Splayd.init
$db.do "UPDATE locks SET job_reservation='0' WHERE id ='1'"

# Daemons
LogdServer.new.run
SplaydServer.new.run
JobdStandard.run

JobdTrace.init
JobdTrace.run

Unseend.run
Statusd.run
Loadavgd.run
Blacklistd.run

#Splayd.localize_all

# end only on interruption
loop do sleep 1000 end
