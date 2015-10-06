# cluster certain event types, and filter out certain records 

# cluster certain ip/geoip lookup events -- this could be much expanded
s/ET\(PRO\)\? POLICY .*\( IP \(Lookup\|Check\)\|whatismyipaddress\|hostip.info\|freegeoip\|geoplugin\|icanhazip\.com\)[^"]\+/Generic IP\/GeoIP Lookup/

# Cluster certain event types
s/\(.*"\(ET RBN\|ET DROP Spamhaus\|ET DROP Dshield\|ET COMPROMISED\|ET DROP Known Bot\|ET CIARMY\|ET CINS\)\)[^\"]\+\(".*\)/\1\3/
s/ET CURRENT_EVENTS HTTP Request to a .*omain/ET CURRENT_EVENTS HTTP Request to a SUSPICIOUS Domain/

# Cluster vulnerable java version alerts to all appear as "ET POLICY Vulnerable Java Version Detected"
s/\(.*"ET POLICY Vulnerable Java Version \)[^ ]\+ Detected"/\1Detected"/

# suppress OSSEC alerts in db for now
/\[OSSEC\]/d
