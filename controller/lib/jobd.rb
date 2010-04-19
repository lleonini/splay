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


class Jobd

	@@threads = {} # to kill
	# To protect all functions that will issue REGISTERs actions.
	@@dlock_jr = DistributedLock.new('job_reservation')

	@@register_timeout = Config::RegisterTimeout
	@@poll_time = Config::JobPollTime
	@@link_log_dir = Config::LinkLogDir
	@@log_dir = Config::LogDir

	def self.run
		return Thread.new do
			main
		end
	end

	def self.main
		begin
			$log.info(">>> Splay Controller Job Daemon")
			while sleep(@@poll_time)
				status_local
				status_registering
				status_running
				kill_max_time
				command
			end
		rescue => e
			$log.fatal(e.class.to_s + ": " + e.to_s + "\n" + e.backtrace.join("\n"))
		end
	end

	def self.init
	end

	def self.status_local
	end

	def self.status_registering
	end

	def self.status_running
	end

	def self.kill_max_time
	end

	def self.command_kill
	end

	# Update job status (and status time)
	def self.set_job_status(id, status, status_msg = "")
		$log.info("Job #{id}: #{status} #{status_msg}")
		$db.do "UPDATE jobs SET
				status='#{status}',
				status_time='#{Time.now.to_i}',
				status_msg='#{status_msg}'
				WHERE id='#{id}'"
	end

	# A fast created json string with the node position or with the futur
	# "to be replaced parameter" _POSITION_
	def self.my_json(list)
		out = '{"ref":"' + list['ref'] + '"'

		if not list['position']
			out += ',"position":_POSITION_'
		else
			out += ',"position":' + (list['position'].to_i + 1).to_s
		end

		if list['type']
			out += ',"type":"' + list['type'].to_s + '"'
		else
			out += ',"type":"head"'
		end

		nodes = ""
		list['nodes'].each do |n|
			nodes = nodes + '{"ip":"' + n['ip'].to_s + '","port":' +
					n['port'].to_s + '},'
		end
		if nodes.size > 0
			nodes = nodes[0, nodes.length - 1]
			out += ',"nodes":[' + nodes + ']'
		else
			out += ',"nodes":[]'
		end
		out += '}'

		return out
	end

	def self.raw_list(job, m_s_s, max = 0)
		list = {}
		list['ref'] = job['ref']
		list['nodes'] = []
		c = 1
		m_s_s.each do |m_s|
			# 0 = full list
			if max > 0
				if c > max then break end
				c += 1
			end
			res = $db.select_one "SELECT ip FROM splayds WHERE id='#{m_s['splayd_id']}'"
			el = {}
			el['id'] = m_s['splayd_id']
			el['ip'] = res['ip']
			el['port'] = m_s['port']
			list['nodes'] << el
		end
		return list
	end

	def self.head_list(job, m_s_s)
		return my_json(raw_list(job, m_s_s, job['list_size'])) # a string now...
	end

	# Return an array of  random list of job['list_size'] elements for each node
	def self.random_lists(job, m_s_s)
		job_list = raw_list(job, m_s_s)

		lists = {}
		pos = 0

		size = job['list_size']
		if job['list_size'] == 0 # all
			size = job_list['nodes'].size - 1 # without the node receiving the list
		end
		if size > job_list['nodes'].size - 1
			size = job_list['nodes'].size - 1
		end

		m_s_s.each do |m_s|

			nodes = job_list['nodes'].dup

			# We remove our node from the job_list.
			me = nodes.slice!(pos)

			# new list for nodes 'me'
			list = {}
			list['ref'] = job['ref']
			list['type'] = 'random'
			# in a rand list, it doesn't means position in nodes
			# but overall position in job
			list['position'] = pos

			list['nodes'] = []
			(1..size).each do
				list['nodes'] << nodes.slice!(rand(nodes.size))
			end
			
			lists[me['id']] = my_json(list)
			pos += 1
		end

		return lists
	end

	# Send the list of everybody selected by the query, to everybody selected by
	# the query.
	# (query should return values with splayd_id)
	def self.send_all_list(job, query)
		m_s_s = $db.select_all query
		
		case job['list_type']
		when 'HEAD' # simple head list of job['list_size'] element

			list_json = head_list(job, m_s_s)
			q_act = ""
			pos = 1
			m_s_s.each do |m_s|
				q_act = q_act + "('#{m_s['splayd_id']}','#{job['id']}','LIST','#{pos}','TEMP'),"
				pos = pos + 1
			end
			q_act = q_act[0, q_act.length - 1]
			$db.do "INSERT INTO actions (splayd_id, job_id, command, position, status)
					VALUES #{q_act}"
			$db.do "UPDATE actions SET data='#{list_json}', status='WAITING'
					WHERE job_id='#{job['id']}' AND command='LIST' AND status='TEMP'"
		when 'RANDOM' # random list of job['list_size'] element

			lists = random_lists(job, m_s_s)
			# Complex list are all differents so they will be sent as a BIG SQL
			# request. Check MySQL packet size for limit.
			# TODO split in multiple request
			q_act = ""
			lists.each do |splayd_id, json|
				q_act += "('#{splayd_id}','#{job['id']}','LIST', '#{json}'),"
			end
			if q_act.size > 0 
				q_act = q_act[0, q_act.length - 1]
				$db.do "INSERT INTO actions (splayd_id, job_id, command, data)
						VALUES #{q_act}"
			end
		end
	end

	# query should return values with splayd_id
	def self.send_start(job, query)
		m_s_s = $db.select_all query
		q_act = ""
		m_s_s.each do |m_s|
			q_act = q_act + "('#{m_s['splayd_id']}','#{job['id']}','START', '#{job['ref']}'),"
		end
		q_act = q_act[0, q_act.length - 1]
		$db.do "INSERT INTO actions (splayd_id, job_id, command, data) VALUES #{q_act}"
	end

	def self.create_filter_query(job)

		version_filter = ""
		if job['splayd_version']
			version_filter += " AND version='#{job['splayd_version']}' "
		end

		distance_filter = ""
		if job['distance'] and job['latitude'] and job['longitude']
			distance_filter =
					" AND longitude IS NOT NULL AND latitude IS NOT NULL AND
				DEGREES(
					ACOS(
						( 
							SIN(RADIANS(#{job['latitude']})) * SIN(RADIANS(latitude))
						)
						+
						( 
							COS(RADIANS(#{job['latitude']}))
							*
							COS(RADIANS(latitude))
							*
							COS(RADIANS(#{job['longitude']} - longitude))
						)
					) * 60 * 1.1515 * 1.61
				) <= '#{job['distance']}'  "
		end

		localization_filter = ""
		if job['localization']
			# If its a continent code.
			countries = countries_by_continent()
			if countries[job['localization']]
				localization_filter = " AND ("
				countries[job['localization']].each do |country|
					localization_filter += "country='#{country}' OR "
				end
				localization_filter = localization_filter[0..(localization_filter.length() - 5)] + ") "
			else
				localization_filter += " AND country='#{job['localization']}' "
			end
		end

		bytecode_filter = ""
		if job['code'][0,4] =~ /\x1BLua/ # Lua Bytecode
			if job['code'][0,5] =~ /\x1BLuaQ/
				bytecode_filter = " AND endianness='#{job['endianness']}' "
				bytecode_filter += " AND bits='#{job['bits']}' "
			else
				status_msg += "The bytecode isn't Lua 5.1 bytecode.\n"
				set_job_status(job['id'], 'NO_RESSOURCES', status_msg)
				next
			end
		end
		
		hostmasks_filter = ""
		if job['hostmasks']
			# TODO split with "|"
			hm_t = job['hostmasks'].gsub(/\*/, "%")
			hostmasks_filter = " AND (ip LIKE '#{hm_t}' OR hostname LIKE '#{hm_t}') "
		end

		resources_filter = "AND splayds.status='AVAILABLE' AND
					max_mem >= '#{job['max_mem']}' AND
					disk_max_size >= '#{job['disk_max_size']}' AND
					disk_max_files >= '#{job['disk_max_files']}' AND
					disk_max_file_descriptors >= '#{job['disk_max_file_descriptors']}' AND
					network_max_send >= '#{job['network_max_send']}' AND
					network_max_receive >= '#{job['network_max_receive']}' AND
					network_max_sockets >= '#{job['network_max_sockets']}' AND
					network_max_ports >= '#{job['network_nb_ports']}' AND
					network_send_speed >= '#{job['network_send_speed']}' AND
					network_receive_speed >= '#{job['network_receive_speed']}' AND
					load_5 <= '#{job['max_load']}' AND
					start_time <= '#{Time.now.to_i - job['min_uptime']}' AND
					max_number > 0 "

		# We don't take splayds already mandatory (see later)
		mandatory_filter = ""
		$db.select_all "SELECT * FROM job_mandatory_splayds
				WHERE job_id='#{job['id']}'" do |mm|
			mandatory_filter += " AND splayds.id!=#{mm['splayd_id']} "
		end

		return "SELECT * FROM splayds WHERE
				1=1
				#{version_filter}
				#{resources_filter}
				#{localization_filter}
				#{bytecode_filter}
				#{mandatory_filter}
				#{hostmasks_filter}
				#{distance_filter}
				ORDER BY RAND()"
	end

	def self.create_job_json(job)
			new_job = {}
			new_job['ref'] = job['ref']
			new_job['code'] = job['code']
			new_job['script'] = job['script']
			new_job['network'] = {}
			new_job['network']['max_send'] = job['network_max_send']
			new_job['network']['max_receive'] = job['network_max_receive']
			new_job['network']['max_sockets'] = job['network_max_sockets']
			new_job['network']['nb_ports'] = job['network_nb_ports']
			if job['udp_drop_ratio'] != 0
				new_job['network']['udp_drop_ratio'] = job['udp_drop_ratio']
			end
			new_job['disk'] = {}
			new_job['disk']['max_size'] = job['disk_max_size']
			new_job['disk']['max_files'] = job['disk_max_files']
			new_job['disk']['max_file_descriptors'] = job['disk_max_file_descriptors']
			new_job['max_mem'] = job['max_mem']
			new_job['keep_files'] = job['keep_files']
			new_job['die_free'] = job['die_free']
			return new_job.to_json
	end

	# http://www.iso.org/iso/country_codes/iso_3166_code_lists/english_country_names_and_code_elements.htm
	def self.countries_by_continent
		countries = {}
		countries['af'] = ['ao', 'bf', 'bi', 'bj', 'bw', 'cd', 'cf', 'cg', 'ci', 'cm',
		'cv', 'dj', 'dz', 'eg', 'eh', 'er', 'et', 'ga', 'gh', 'gm', 'gn', 'gq', 'gw',
		'ke', 'km', 'lr', 'ls', 'ly', 'ma', 'mg', 'ml', 'mr', 'mu', 'mw', 'mz', 'na',
		'ne', 'ng', 're', 'rw', 'sc', 'sd', 'sh', 'sl', 'sn', 'so', 'st', 'sz', 'td',
		'tg', 'tn', 'tz', 'ug', 'yt', 'za', 'zm', 'zw']
		countries['an'] = ['aq', 'bv', 'gs', 'hm', 'tf'] 
		countries['as'] = ['ae', 'af', 'am', 'az', 'bd', 'bh', 'bn', 'bt', 'cc', 'cn',
		'cx', 'cy', 'ge', 'hk', 'id', 'il', 'in', 'io', 'iq', 'ir', 'jo', 'jp', 'kg',
		'kh', 'kp', 'kr', 'kw', 'kz', 'la', 'lb', 'lk', 'mm', 'mn', 'mo', 'mv', 'my',
		'np', 'om', 'ph', 'pk', 'ps', 'qa', 'sa', 'sg', 'sy', 'th', 'tj', 'tl', 'tm',
		'tr', 'tw', 'uz', 'vn', 'ye']
		countries['eu'] = ['ad', 'al', 'at', 'ax', 'ba', 'be', 'bg', 'by', 'ch', 'cz',
		'de', 'dk', 'ee', 'es', 'fi', 'fo', 'fr', 'gb', 'gg', 'gi', 'gr', 'hr', 'hu',
		'ie', 'im', 'is', 'it', 'je', 'li', 'lt', 'lu', 'lv', 'mc', 'md', 'me', 'mk',
		'mt', 'nl', 'no', 'pl', 'pt', 'ro', 'rs', 'ru', 'se', 'si', 'sj', 'sk', 'sm',
		'ua', 'va']
		countries['na'] = ['ag', 'ai', 'an', 'aw', 'bb', 'bm', 'bs', 'bz', 'ca', 'cr',
		'cu', 'dm', 'do', 'gd', 'gl', 'gp', 'gt', 'hn', 'ht', 'jm', 'kn', 'ky', 'lc',
		'mq', 'ms', 'mx', 'ni', 'pa', 'pm', 'pr', 'sv', 'tc', 'tt', 'us', 'vc', 'vg',
		'vi']
		countries['oc'] = ['as', 'au', 'ck', 'fj', 'fm', 'gu', 'ki', 'mh', 'mp', 'nc',
		'nf', 'nr', 'nu', 'nz', 'pf', 'pg', 'pn', 'pw', 'sb', 'tk', 'to', 'tv', 'um',
		'vu', 'wf', 'ws']
		countries['sa'] = ['ar', 'bo', 'br', 'cl', 'co', 'ec', 'fk', 'gf', 'gy', 'pe',
		'py', 'sr', 'uy', 've']
		return countries
	end


end
