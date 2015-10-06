# nsm_event_graph
Script to generate high level link graphs of Sguil database events on Security Onion server/standalone systems

What nsm_event_graph.pl does, and what config files are involved:

Read the last specified number of hours of events from the sguil db, ending up with CSV 3-tuples of "source ip","sig name","itarget ip"

Use sed to cluster certain event types, and to filter out certain records by criteria in the 3-tuples
        nsm_event_graph.csv.sed

Optionally use awk for field-specific filtering (like source or target network) and for clustering certain destination IPs
        nsm_event_graph.csv.awk
        (only done if this config file exists)

Use awk on the resulting 3-tuples to generate a list of IPs involved in non-reputational events.  Reputational events are events that are not worthy of showing up on the graph unless other more interesting events are involved as well.
        nsm_event_graph.rep.awk

Use that list to remove all records except those involving IPs in the list.

Add a 4th and 5th field (source count and target count) to the record as total counts of the source and dest IPs.  These counts will be included in the source and target node labels as well as influence their color if the afterglow prop file is configured for that.

Resolve IP addresses to names where possible and add them to the saddr and daddr fields

Optionally use sed to filter out additional records based on host or domain name
        nsm_event_graph.csv.sed.post
        (only done if this config file exists)

Feed the final 5-tuple to afterflow to form a DOT file according to the specifications in the afterglow prop file
        nsm_event_graph.prop

Use sed to transform the dot file to have a proper title, data-specific customizations such as subnet-specific node shapes, and other general graph tweaks to optimize layout.
        nsm_event_graph.dot.sed

Feed the updated DOT file into Graphviz (neato) to make a gif file
