#!/bin/bash
#
# nsm_event_graph.pl - build a Sguil event link graph based on the last N hours of events in the Sguil database.  
# by Kevin Branch (kevin@branchnetconsulting.com)
#
# Tested on Ubuntu 12.04 running a standalone install of Security Onion.  It would likely work the same on a server install of Security Onion as well.
#
# Prerequisites:
#
#	AfterGlow 1.6.5 from http://afterglow.sourceforge.net/.  Put afterglow.pl script in the system path.  Something like this:
#
#       	wget http://pixlcloud.com/wp-content/plugins/download-monitor/download.php?id=11 -O afterglow-1.6.5.tar.gz
#		tar zxvf afterglow-1.6.5.tar.gz
#		cp afterglow/afterglow.pl /usr/bin/
#		
#	Graphviz - get and install the latest stable Graphviz.  The Ubuntu 12.04 package is too old, but Security Onion depends on it, so install from tarball in parellel to old version that is already present, like this:
# 
#		TARGET_GV_VER="2.38.0"
#		wget http://www.graphviz.org/pub/graphviz/stable/SOURCES/graphviz-$TARGET_GV_VER.tar.gz
#		tar zxvf graphviz-$TARGET_GV_VER.tar.gz
#		cd graphviz-$TARGET_GV_VER
#		./configure && make && make install
#
# Usage example:    sudo nsm_event_graph.pl 24
# 		    (builds an event graph ./graph.png based on the past 24 hours of events in Sguil, according to the specifications of various config files in the local directory)
#		

HOURS=$1

# Set what directory to read config files from, where to put working files, and where to write the final graph file
CONFIG_DIR=~/nsm_event_graph
WORKING_DIR=~/nsm_event_graph
GRAPH_FILE=~/nsm_event_graph/nsm_event_graph.gif

if [ ! -e $WORKING_DIR ]; then
	mkdir $WORKING_DIR 
fi

# move to working directory
cd $WORKING_DIR

rm -f nsm_event_graph.{csv,dot,1,2,3,4} icount ip.resolved noreps $GRAPH_FILE

# Get 3-column CSV of mysql snort data for the specified time interval (from $HOURS ago to the present).
sudo mysql securityonion_db -e "SELECT inet_ntoa(src_ip) as src_ip, signature as sig_name, inet_ntoa(dst_ip) as dst_ip FROM securityonion_db.event WHERE DATE_SUB(NOW(),INTERVAL $HOURS hour) <= timestamp;" | sed 's/\t/","/g;s/^/"/;s/$/"/;s/\n//' | sed '1d' > nsm_event_graph.csv

cp nsm_event_graph.csv nsm_event_graph.1

# replace commas inside of quoted text fields since this file's fields will be split by commas
while [[ `egrep ',"[^"]+,' nsm_event_graph.csv` ]]; do
	sed -i 's/\(^.*,"[^"]\+\),/\1 /g;s/  / /g' nsm_event_graph.csv
done

# Cluster certain event types, omit certain nodes, or do other filtering according to nsm_event_graph.sed file
sed -i -f $CONFIG_DIR/nsm_event_graph.csv.sed nsm_event_graph.csv

cp nsm_event_graph.csv nsm_event_graph.2

# if an awk file is present to act upon the csv file, then use it now to perform extended filtering and aggregation 
if [ -f $CONFIG_DIR/nsm_event_graph.csv.awk ]; then
	awk -f $CONFIG_DIR/nsm_event_graph.csv.awk nsm_event_graph.csv > nsm_event_graph.awk
	rm -f nsm_event_graph.csv
	mv nsm_event_graph.awk nsm_event_graph.csv
fi

cp nsm_event_graph.csv nsm_event_graph.3


# 
# eliminate all events whose IPs are involved solely in reputational event types
#
# Get list of all local IPs involved in non-reputational events.  No events involving these IPs should be graphed
awk -f $CONFIG_DIR/nsm_event_graph.rep.awk nsm_event_graph.csv | grep "NOREP" | cut -d, -f1 | sort | uniq > noreps
# cull out all events except those involving local IPs that are involved in non-reputational events.  So no IPs involved solely in reputational events will show up.
grep -F -f noreps nsm_event_graph.csv > muchbetter.csv
rm -f nsm_event_graph.csv
mv muchbetter.csv nsm_event_graph.csv

cp nsm_event_graph.csv nsm_event_graph.4

#
# this section gets counts for source IP, target IP, and event names, and appends the count to the appropriate fields in the csv file
#

X=`awk -F "\"*,\"*" '{print $1,"\" \""$3}' nsm_event_graph.csv | sed 's/ " /" /'`
echo $X | sed 's/" "/"\n"/g' | sort | uniq -c | sed 's/ "/,"/g' | awk '{print $1,$2,$3}' > icount

cat nsm_event_graph.csv | sort | uniq > nsm_event_graph.tmp
rm -f nsm_event_graph.csv
mv nsm_event_graph.tmp nsm_event_graph.csv

sed -i 's/$/,sCount,tCount/' nsm_event_graph.csv

cat icount | while read line; do
 COUNT="`echo $line | cut -d, -f1`"
 IP="`echo $line | cut -d, -f2`"
 sed -i "s/^\($IP,.*,\)sCount\(,.*\)/\1$COUNT\2/" nsm_event_graph.csv
 sed -i "s/^\(.*,$IP,.*,\)tCount$/\1$COUNT/" nsm_event_graph.csv
done

sed -i 's/ \"/\"/g' nsm_event_graph.csv

sed -i 's/^\("[^"]\+\)\(".*\)\,\([0-9]\+\),\([0-9]\+\)$/\1 (\3)\2,\3,\4/' nsm_event_graph.csv
sed -i 's/^\(.*\)",\([0-9]\+\),\([0-9]\+\)$/\1 (\3)",\2,\3/' nsm_event_graph.csv

#
# done with field counting section
#


# Generate ip.resolved table, looking up IPs in various possible ways in hopes of turning up a name
rm -f ip.resolved
touch ip.resolved
for IP in `cut -d\" -f2 icount | egrep "^[0-9]+\.[0-9]+\.[0-9]+"`; do
	# try to lookup name from IP using DNS 
	NAME=`RES_OPTIONS="timeout:1 attempts:1" dig +short -x $IP | head -n1 | sed 's/\.$//'`
        if [ "$NAME" != "" ]; then
                NAME=`echo $NAME | tail -n1 | sed 's/.* \(.*\)\.$/\1/'`
                echo "$IP,$NAME" >> ip.resolved
        fi
done

cat ip.resolved | while read line; do
        IP=`echo $line | cut -d, -f1`
        NAME=`echo $line | cut -d, -f2`
        sed -i "s/^\(.*\"$IP ([0-9]\+)\)\\(\".*\)$/\1\\\\n$NAME\2/" nsm_event_graph.csv
done

# If a post processing sed file is present to act upon the csv file, then use it now to perform filtering involving FQDNs.
if [ -f $CONFIG_DIR/nsm_event_graph.csv.sed.post ]; then
	sed -i -r -f $CONFIG_DIR/nsm_event_graph.csv.sed.post nsm_event_graph.csv
fi

cat nsm_event_graph.csv | afterglow.pl -a -e1 -c $CONFIG_DIR/nsm_event_graph.prop > nsm_event_graph.dot 2> /dev/null

sed -i -f $CONFIG_DIR/nsm_event_graph.dot.sed nsm_event_graph.dot

cat nsm_event_graph.dot | /usr/local/bin/neato -Earrowsize=0.75 -Nfontsize=8 -Tgif -o $GRAPH_FILE 2> /dev/null
