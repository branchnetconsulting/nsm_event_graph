BEGIN { FS = "\"" };
{

	# Classify certain events as reputational.  These events are only of contextual value and should not appear in the graph unless they are connected to other events that are not reputational.
	# The term "reputational" is being loosely used here.  Any types of events that are not important by themselves are intended for this category.
        if ($4 == "ET RBN" || $4 == "ET DROP Spamhaus" || $4 == "ET DROP Dshield" || $4 == "ET DROP Known Bot" || $4 == "ET COMPROMISED" || $4 == "ET CIARMY" || $4 ~ "^Bro Intel::.*" || $4 ~ "ET POLICY Vulnerable Java Version Detected"  || $4 == "Generic IP/GeoIP Lookup" || $4 ~ "ET CNC Zeus Tracker" || $4 ~ "ET CNC Feodo Tracker" || $4 ~ "BetterSurf.* SSL Cert")
                TYPE="REP";
        else
                TYPE="NOREP";

	# figure out which IP is the local IP (source or target)
        if ($2 ~ "^(10\\..*|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)")
                LOCAL=$2;
        if ($6 ~ "^(10\\..*|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)")
                LOCAL=$6;

        print "\""LOCAL"\",\""TYPE"\""
}

