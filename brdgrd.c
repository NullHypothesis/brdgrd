/* Copyright (C) 2012 Philipp Winter (philipp.winter@kau.se)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * =======================================================================
 *
 * This program requires iptables rules feeding it with data. See the
 * README for details.
 */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <libnet.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* used for connection logging */
#define ACCEPTED	1
#define REJECTED	0

/* used to print verbose messages to stdout */
#define VRB(...) \
	if (verbose) { \
		printf("[V] "); \
		print(__VA_ARGS__); \
	}


/* the hash table and global config variables */
static int verbose = 0;
static int queue_number = 1;
static int win_size = 80;
static char libnet_err_buf[LIBNET_ERRBUF_SIZE] = { 0 };


/* Wrapped by the VRB() macros.
 */
static void print( const char *fmt, ... ) {

	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}


/* Prints a human readable timestamp with millisecond granularity to stdout.
 */
static inline void print_time( void ) {

	struct timeval tv = { 0, 0 };
	struct tm *tmp = NULL;
	time_t now = time(NULL);
	char timestr[50] = { 0 };

	if (gettimeofday(&tv, NULL) == -1) {
		perror("gettimeofday() failed");
		return;
	}

	if ((tmp = localtime(&now)) == NULL) {
		VRB("localtime() failed.\n");
		return;
	}

	strftime(timestr, sizeof(timestr), "%T", tmp);

	VRB("Time: %s.%03ld\n", timestr, tv.tv_usec/1000);
}


/* Quick check if we are dealing with a TCP SYN/ACK segment. If not,
 * 0 is returned.
 */
static inline int tcp_synack_segment( struct iphdr *iphdr,
	struct tcphdr *tcphdr ) {

	/* check for IP protocol field */
	if (iphdr->protocol != 6) {
		return 0;
	}

	/* check for set bits in TCP hdr */
	if (tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->psh == 0 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 1 &&
		tcphdr->fin == 0) {
		return 1;
	}

	return 0;
}

/* This function tries to rewrite the TCP window size in the SYN/ACK which is
 * sent by the Tor bridge to the client. This is done without the bridge
 * knowing and hence a dirty hack. The purpose is to force the client to send a
 * small TCP segment after the handshake so that the cipher list inside the TLS
 * client hello gets fragmented across several segments (the GFC does not
 * conduct packet reassembly).
 */
int rewrite_win_size( unsigned char *packet ) {

	struct iphdr *iphdr = (struct iphdr *) packet;
	struct tcphdr *tcphdr = (struct tcphdr *) (packet + (iphdr->ihl * 4));
	static libnet_t *ln = NULL;

	VRB("Window size before rewriting: %u\n", ntohs(tcphdr->window));
	tcphdr->window = htons(win_size);

	if (!ln) {
		VRB("Initializing libnet for checksum calculation.\n");
		/* initialize libnet for calculating the new checksum */
		if ((ln = libnet_init(LIBNET_LINK, NULL, libnet_err_buf)) == NULL) {
			fprintf(stderr, "Error: libnet_init() failed.\n");
			return 1;
		}
	}

	/* recalculate tcp checksum */
	if (libnet_do_checksum(ln, packet, 6, ntohs(iphdr->tot_len) - (iphdr->ihl*4)) == -1) {
		fprintf(stderr, "Error while recalculating TCP segment checksum.\n");
		return 1;
	}

	return 0;
}


/* Callback function which is called for every incoming packet.
 * It issues a verdict for every packet which is either ACCEPT
 * or DROP.
 * This function deals with untrusted network data.
 */
int callback( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
	void *data ) {

	struct iphdr *iphdr = NULL;
	struct tcphdr *tcphdr = NULL;
	struct nfqnl_msg_packet_hdr *ph = NULL;
	unsigned char *packet= NULL;
	int id = 0;

	printf("\n");
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	} else {
		VRB("Error - the function nfq_get_msg_packet_hdr() failed.\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	/* try to get packet (header + payload) */
	if (nfq_get_payload(nfa, (char **) &packet) == -1) {
		VRB("Error - the function nfq_get_payload() failed.\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	/* initialize pointers to IP and TCP headers */
	iphdr = (struct iphdr *) packet;
	/* RFC 791 defines that the IHL's minimum value is 5 */
	if ((iphdr->ihl < 5) || (iphdr->ihl > 15)) {
		VRB("Error - the IHL (\\x%x) in the IP header is invalid.\n", iphdr->ihl);
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	tcphdr = (struct tcphdr *) (packet + (iphdr->ihl * 4));

	print_time();

	/* check if we are dealing with a TCP SYN/ACK segment */
	if (tcp_synack_segment(iphdr, tcphdr)) {

		/* we got a SYN/ACK and the window size is set: let's rewrite */
		VRB("Attempting to rewrite TCP window size in SYN/ACK.\n");
		if (rewrite_win_size(packet) != 0) {
			VRB("Rewriting the window size failed. This is probably a bug!\n");
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}

		VRB("Reinjecting SYN/ACK with window size set to %d.\n", win_size);
		return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iphdr->tot_len), packet);

	/* something != SYN/ACK */
	} else {
		fprintf(stderr, "We received something other than a TCP SYN/ACK segment. " \
			"Are your iptables rules correct?\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}


/* Help output explaining the user how to use the program.
 */
void help( const char *argv ) {

	printf("\nUsage: %s [OPTIONS] \n\n", argv);
	printf("\tRe-check your iptables rules if the program does not receive any data.\n\n");
	printf("Options:\n");
	printf("\t-h, --help\t\tShow this help message and exit.\n");
	printf("\t-v, --verbose\t\tEnable verbose mode and print much information.\n");
	printf("\t-w, --winsize\t\tRewrite the bridge's announced TCP window size (default=%d).\n", win_size);
	printf("\t-q, --queue=NUM\t\tThe NFQUEUE number to attach to (default=%d).\n", queue_number);
}


/* Initializes libnetfilter_queue. If something fails during the process,
 * 1 is returned. If all is fine, 0 is returned.
 */
int init_libnfq( struct nfq_handle **h, struct nfq_q_handle **qh ) {

	VRB("Opening library handle.\n");
	*h = nfq_open();
	if (!(*h)) {
		fprintf(stderr, "Error: nfq_open() failed.\n");
		return 1;
	}

	VRB("Unbinding existing nf_queue handler for AF_INET (if any).\n");
	if (nfq_unbind_pf(*h, AF_INET) < 0) {
		fprintf(stderr, "Error: nfq_unbind_pf() failed.\n");
		return 1;
	}

	VRB("Binding nfnetlink_queue as nf_queue handler for AF_INET.\n");
	if (nfq_bind_pf(*h, AF_INET) < 0) {
		fprintf(stderr, "Error: nfq_bind_pf() failed.\n");
		return 1;
	}

	VRB("Binding this socket to queue '%d'.\n", queue_number);
	*qh = nfq_create_queue(*h,  queue_number, &callback, NULL);
	if (!(*qh)) {
		fprintf(stderr, "Error: nfq_create_queue() failed.\n");
		return 1;
	}

	VRB("Setting copy_packet mode.\n");
	if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Error: can't set packet_copy mode.\n");
		return 1;
	}

	return 0;
}


int main( int argc, char **argv ) {

	int fd = 0;
	int rv = 0;
	int current_opt = 0;
	int option_index = 0;
	char buf[4096] __attribute__ ((aligned)) = { 0 };
	struct nfq_handle *h = NULL;
	struct nfq_q_handle *qh = NULL;

	struct option long_options[] = {
		{"verbose",		no_argument,		&verbose,	1},
		{"help",		no_argument,		NULL,	'h'},
		{"winsize",		required_argument,	NULL, 	'w'},
		{"queue",		required_argument,	NULL,	'q'},
		{0, 0, 0, 0}
	};

	/* disable buffering for stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

	/* parse cmdline options */
	while (1) {

		current_opt = getopt_long(argc, argv, "hvq:w:", long_options, &option_index);

		/* end of options? */
		if (current_opt == -1) {
			break;
		}

		switch (current_opt) {
			case 'v': verbose = 1;
				break;
			case 'w': win_size = atoi(optarg);
				break;
			case 'q': queue_number = atoi(optarg);
				break;
			case 'h': help(argv[0]);
				return 0;
			case '?': help(argv[0]);
				return 1;
		}
	}

	/* dump configuration to stdout for the user to verify */
	VRB("Configuration:\n\tnetfilter queue = %d\n\twindow size = %d\n", \
		queue_number, win_size);

	/* exit if initialization failed */
	if (init_libnfq(&h, &qh) != 0) {
		fprintf(stderr, "Exiting because libnetfilter_queue init failed.\n");
		return 1;
	}

	fd = nfq_fd(h);

	VRB("Waiting for incoming packets...\n");
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	VRB("Unbinding from queue 0.\n");
	nfq_destroy_queue(qh);

	VRB("Closing library handle.\n");
	nfq_close(h);

	return 0;
}
