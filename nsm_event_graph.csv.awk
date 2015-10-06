BEGIN { FS = "\"" };
{

	# Aggregate targets of certain rule groups

        if ($4 == "ET RBN" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="RBN IP(s)";
        if ($4 == "ET RBN" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="RBN IP(s)";

        if ($4 == "ET CIARMY" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="CIARMY IP(s)";
        if ($4 == "ET CIARMY" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="CIARMY IP(s)";

        if ($4 == "ET DROP Spamhaus" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="SPAMHAUS IP(s)";
        if ($4 == "ET DROP Spamhaus" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="SPAMHAUS IP(s)";

        if ($4 == "ET DROP Dshield" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="DSHIELD IP(s)";
        if ($4 == "ET DROP Dshield" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="DSHIELD IP(s)";

        if ($4 == "ET DROP Known Bot" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="BOT IP(s)";
        if ($4 == "ET DROP Known Bot" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="BOT IP(s)";

        if ($4 == "ET COMPROMISED" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="COMPROMISED IP(s)";
        if ($4 == "ET COMPROMISED" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="COMPROMISED IP(s)";

        if ($4 == "Generic IP/GeoIP Lookup" && $2 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $2="IP Lookup Service(s)";
        if ($4 == "Generic IP/GeoIP Lookup" && $6 !~ "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)") $6="IP Lookup Service(s)";

        print "\""$2"\",""\""$4"\",\""$6"\""
}
