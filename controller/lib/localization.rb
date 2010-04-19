require "#{File.dirname(__FILE__)}/geoip"

class Localization

	@@loc_db = nil
	def self.get(ip)
		if not @@loc_db
			@@loc_db = Net::GeoIP.new("#{File.dirname(__FILE__)}/GeoLiteCity.dat")
		end
		return Net::GeoIP::Record.new(@@loc_db, ip)
	end
end
