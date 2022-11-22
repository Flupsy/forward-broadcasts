#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#define DEBUG(s)	if(flag_debug) fprintf(stderr, "%s\n", (s));

static char *broadcast_filter="broadcast and dst host 255.255.255.255";

char *argv0;
int flag_debug=0;


static pcap_t *init_listen_dev(char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask, net;
	struct bpf_program fp;
	pcap_t *pc;

	DEBUG("init_listen_dev()");

	if(pcap_lookupnet(dev, &net, &mask, errbuf)<0) {
		fprintf(stderr, "Can't get information for %s: %s\n", dev, errbuf);
		return NULL;
	}

	if(!(pc=pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf))) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return NULL;
	}

	if(pcap_compile(pc, &fp, broadcast_filter, 0, net)<0) {
		pcap_perror(pc, "pcap_compile");
		return NULL;
	}

	if(pcap_setfilter(pc, &fp)<0) {
		pcap_perror(pc, "pc_setfilter");
		return NULL;
	}

	DEBUG("init_listen_dev() done");

	return pc;
}


static int init_output_dev(char *dev)
{
	int s;
	int optval=1;

	DEBUG("init_output_dev()");

	if((s=socket(AF_INET, SOCK_RAW, IPPROTO_RAW))<0) {
		perror("Can't make raw socket");
		return 0;
	}

	if(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev))<0) {
		perror("Can't bind socket to device");
		return 0;
	}

	if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval))<0) {
		perror("Can't set broadcast option on socket");
		return 0;
	}

	DEBUG("init_output_dev() done");

	return s;
}


static int process_packet(pcap_t *in, int out)
{
	struct pcap_pkthdr *header;
	const u_char *data;
	struct ip *ip;
	struct sockaddr_in addr;

	DEBUG("process_packet()");

	if(pcap_next_ex(in, &header, &data)==PCAP_ERROR) {
		pcap_perror(in, argv0);
		return 0;
	}

	ip=(struct ip *) (data+14);

	addr.sin_family=AF_INET;
	memcpy(&addr.sin_addr, &ip->ip_dst.s_addr, 4);

	if(sendto(out, (u_char *) ip, header->len-14, 0, (struct sockaddr *) &addr, sizeof(addr))<0) {
		perror("send");
		return 0;
	} else {
		DEBUG("  sent packet");
	}

	DEBUG("process_packet() done");

	return 1;
}


static void usage(void)
{
	fprintf(stderr, "usage: %s [-d] <listen if> <output if>\n", argv0);
	fprintf(stderr, "       -d  print debug messages, and don't fork\n");
}


int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	pcap_t *pc;
	pid_t pid;
	int s, opt;

	argv0=argv[0];

	while((opt=getopt(argc, argv, "d"))!=-1) {
		switch(opt) {
		case 'd':
			flag_debug=1;
			break;
		default:
			usage();
			return 1;
		}
	}

	if(argc-optind!=2) {
		usage();
		return 1;
	}

	if(flag_debug) {
		DEBUG("debug mode, not forking");
	} else {
		if((pid=fork())<0) {
			perror("fork");
			return 1;
		} else if(pid!=0)
			exit(0);

		setsid();

		if((pid=fork())<0) {
			perror("fork");
			return 1;
		} else if(pid!=0)
			exit(0);
	}

	if(!(pc=init_listen_dev(argv[optind])))
		return 1;

	if(!(s=init_output_dev(argv[optind+1])))
		return 1;

	for(;;) {
		if(!process_packet(pc, s))
			break;
	}

	pcap_close(pc);

	return 0;
}
