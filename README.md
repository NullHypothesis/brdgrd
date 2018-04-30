brdgrd (Bridge Guard)
=====================

*UPDATE: Rumour has it that brdgrd is no longer working because the GFW seems to
do TCP stream reassembly now.*

Brdgrd is short for "bridge guard": A small tool that is meant to protect Tor
bridges from being [scanned](https://gist.github.com/da3c7a9af01d74cd7de7) (and
as a result [blocked](http://www.cs.kau.se/philwint/static/gfc/)) by the Great
Firewall of China.

Brdgrd runs in user space and makes use of the libnetfilter_queue mechanism (and
hence only runs on Linux) to move packets from kernel into user space. Only TCP
SYN/ACK segments are passed into user space because brdgrd is only interested in
TCP handshakes and not in established connections. Hence, there are virtually no
performance implications.

Brdgrd intercepts the SYN/ACK segment that a Tor bridge sends to its client.  It
then rewrites the TCP window size announced in this segment. The window size is
rewritten to a smaller, randomly chosen value. That way, the client "fragments"
its cipher list inside the TLS client hello. The GFW will not recognize the
cipher list and as a result will not scan the bridge.

Brdgrd needs iptables rules to feed it with data. The following script passes
all Tor-related SYN/ACKs to brdgrd:

    iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport $TORPORT -j NFQUEUE --queue-num 0

You can compile brdgrd by running `make` and then start it by running `sudo
./brdgrd`. Keep in mind that the above iptables rule tries to push SYN/ACKs to
userspace. If brdgrd is not running, Tor cannot handle new connections because
there is no userspace program to process the SYN/ACK segments.

It is possible to set the `CAP_NET_ADMIN` capability for the brdgrd executable
so that you do not need root privileges to run the binary:

    sudo setcap cap_net_admin=ep ./brdgrd

Please send patches, suggestions, and comments to phw@nymity.ch  
My OpenPGP fingerprint is: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
