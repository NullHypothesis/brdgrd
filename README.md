brdgrd (Bridge Guard)
===

brdgrd is short for ``bridge guard'': A program which is meant to protect
[Tor](https://www.torproject.org) bridges from being *scanned* (and as a result
*blocked*) by the Great Firewall of China [1,2].

The program runs in user space and makes use of
[libnetfilter_queue](http://www.netfilter.org/projects/libnetfilter_queue/index.html)
(and hence only runs on Linux) to get packets passed from kernel to user space.
Only TCP *SYN/ACK* segments have to be passed to user space. Brdgrd is only
interested in TCP handshakes and not in established TCP connections. Once a TCP
connection is established, brdgrd does not interfere with it. Hence, there are
virtually no performance implications.

Brdgrd basically intercepts the SYN/ACK sent by the bridge to the client and
*rewrites* the TCP window size which is announced by the bridge. The window size
is rewritten to a smaller, randomly chosen value. That way, the client
``fragments'' the cipher list inside the TLS client hello. The GFC will not
recognize the cipher list (it does not seem to conduct TCP stream reassembly at
this point) and as a result will not scan the bridge.

Brdgrd needs iptables rules to feed it with data. The following script passes
all Tor-related SYN/ACKs to brdgrd:

	iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport $TORPORT -j NFQUEUE --queue-num 0

If you only want to deal with connections coming from Chinese networks, you can
use the following script which makes use of ipset (thanks to murb):

	#!/bin/bash
	# set the port to your needs
	TORPORT=443
	
	# download latest APNIC data for Chinese networks
	if [ ! -e delegated-apnic-latest ]; then
		wget http://ftp.apnic.net/stats/apnic/delegated-apnic-latest
	fi
	# parse data (the tool 'aggregate' is needed)
	CN=`cat delegated-apnic-latest |
		awk -F\| '/^apnic\|CN\|ipv4\|/ { print $4"/" 32-log($5)/log(2) }' |
		aggregate -q -`
	RETVAL=$?
	[ $RETVAL -eq 0 ] && echo "Successfully parsed chinese network list."
	[ $RETVAL -ne 0 ] && (echo "Failure in parsing chinese network list." ; exit)
	
	ipset create china hash:net hashsize 4096
	
	for NET in $CN; do
		ipset add china $NET
	done
	iptables -N CHINA
	iptables -A CHINA -p tcp --tcp-flags SYN,ACK SYN,ACK --sport $TORPORT -j NFQUEUE --queue-num 1
	iptables -A OUTPUT -m set --match-set china dst -j CHINA

Afterwards, you can compile brdgrd by typing `make` and start it by typing
`sudo ./brdgrd`. Keep in mind that the above iptables rules try to push
SYN/ACKs to userspace. If brdgrd is not running, new (Chinese) connections can
not be handled by Tor since there is no userspace program to process the data.

It is possible to set the *CAP_NET_ADMIN* capability for the brdgrd executable
so that you do not need root privileges to run the binary: `sudo setcap
cap_net_admin=ep ./brdgrd`.

Please send patches, suggestions and comments to philipp.winter@kau.se  
My GnuPG fingerprint is: `2A9F 5FBF 714D 42A9 F82C 0FEB 268C D15D 2D08 1E16`

[1] [https://gist.github.com/da3c7a9af01d74cd7de7](https://gist.github.com/da3c7a9af01d74cd7de7)  
[2] [http://www.cs.kau.se/philwint/static/gfc/](http://www.cs.kau.se/philwint/static/gfc/)
