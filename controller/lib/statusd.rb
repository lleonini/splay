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


class Statusd
	@@status_interval = Config::StatusInterval
	def self.run
		return Thread.new do
			main
		end
	end

	def self.main
		begin
			$log.info(">>> Splay Controller Status Daemon")
			while sleep(@@status_interval)
				# We add status action for splayds where some jobs are running
				$db.select_all "SELECT DISTINCT splayd_id FROM splayd_jobs
						WHERE status='RUNNING'" do |m_s|

					# If we have not already a pending command.
					action = $db.select_one "SELECT * FROM actions WHERE
							splayd_id='#{m_s['splayd_id']}' AND
							command='STATUS'"

					if not action
						$db.do "INSERT INTO actions SET
								splayd_id='#{m_s['splayd_id']}',
								command='STATUS'"
					end
				end
			end
		rescue => e
			$log.fatal(e.class.to_s + ": " + e.to_s + "\n" + e.backtrace.join("\n"))
		end
	end
end
