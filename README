brdgrd (Bridge Guard)

brdgrd is short for ``bridge guard'': A program which is meant to protect Tor
bridges from being scanned (and as a result blocked) by the Great Firewall of
China [1,2].

The program runs in user space and makes use of libnetfilter_queue (and hence
only runs on Linux) to get packets passed from kernel to user space. Only TCP
SYN/ACK segments have to be passed to user space. Brdgrd is only interested in
TCP handshakes and not in established TCP connections. Once a TCP connection is
established, brdgrd does not interfere with it. Hence, there are virtually no
performance implications.

Brdgrd basically intercepts the SYN/ACK sent by the bridge to the client and
rewrites the TCP window size which is announced by the bridge. The window size
is rewritten to a smaller, randomly chosen value. That way, the client
``fragments'' the cipher list inside the TLS client hello. The GFC will not
recognize the cipher list (it does not seem to conduct TCP stream reassembly at
this point) and as a result will not scan the bridge.

Brdgrd needs iptables rules to feed it with data. The following script passes
all Tor-related SYN/ACKs to brdgrd:

iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport $TORPORT -j NFQUEUE --queue-num 0

Afterwards, you can compile brdgrd by typing ``make'' and start it by typing
``sudo ./brdgrd''. Keep in mind that the above iptables rule tries to push
SYN/ACKs to userspace. If brdgrd is not running, new connections can not be
handled by Tor since there is no userspace program to process the data.

It is possible to set the CAP_NET_ADMIN capability for the brdgrd executable so
that you do not need root privileges to run the binary:
``sudo setcap cap_net_admin=ep ./brdgrd''.

Please send patches, suggestions and comments to phw@torproject.org.
My OpenPGP fingerprint is: B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0

[1] https://gist.github.com/da3c7a9af01d74cd7de7
[2] http://www.cs.kau.se/philwint/static/gfc/
