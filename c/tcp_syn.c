/*
        TCP RAW SOCKET EXAMPLE
        Murat Balaban [murat@enderunix.org]
        You should've received a copy of BSD-style license with the tarball.
        See COPYING for copyright info.
*/
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	uint16_t tcp_len;
	struct tcphdr tcp;
};

union generic_addr {
    struct in_addr in4;
    struct in6_addr in6;
};

struct pcap_args {
    union generic_addr dst_addr;
    union generic_addr src_addr;
    int type;
    uint16_t dst_port;
};

uint16_t in_cksum(uint16_t *addr, int len)
{
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// sourced from http://www.pdbuchan.com/rawsock/tcp6_ll.c
uint16_t
tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
    uint32_t lvalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
    ptr += sizeof (iphdr.ip6_src);
    chksumlen += sizeof (iphdr.ip6_src);

    // Copy destination IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
    ptr += sizeof (iphdr.ip6_dst);
    chksumlen += sizeof (iphdr.ip6_dst);

    // Copy TCP length to buf (32 bits)
    lvalue = htonl (sizeof (tcphdr));
    memcpy (ptr, &lvalue, sizeof (lvalue));
    ptr += sizeof (lvalue);
    chksumlen += sizeof (lvalue);

    // Copy zero field to buf (24 bits)
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    return in_cksum((uint16_t *) buf, chksumlen);
}

uint16_t in_cksum_tcp(int src, int dst, uint16_t *addr, int len) {
	struct psd_tcp pseudohdr;

	memset(&pseudohdr, 0, sizeof(pseudohdr));
	pseudohdr.src.s_addr = src;
	pseudohdr.dst.s_addr = dst;
	pseudohdr.pad = 0;
	pseudohdr.proto = IPPROTO_TCP;
	pseudohdr.tcp_len = htons(len);
	memcpy(&(pseudohdr.tcp), addr, len);
	return in_cksum((uint16_t *)&pseudohdr, 12 + len);
}

void set_ip_header(struct ip *ip, struct in_addr dst_addr, struct in_addr src_addr) {
    
	ip->ip_hl = 0x5;
	ip->ip_v = 0x4;
	ip->ip_tos = 0x0;
	ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); 
	ip->ip_id = htons(12830);
	ip->ip_off = 0x0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = 0x0;
	ip->ip_src = src_addr;
	ip->ip_dst = dst_addr;
	ip->ip_sum = in_cksum((uint16_t *)&ip, sizeof(ip));
}

void set_ip6_header(struct ip6_hdr *ip6, struct in6_addr dst_addr, struct in6_addr src_addr) {
    int status;
    ip6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    ip6->ip6_plen = htons (20); // payload of one tcp header with no options
    ip6->ip6_nxt = IPPROTO_TCP;
    ip6->ip6_hops = 255;
    ip6->ip6_src = src_addr;
    ip6->ip6_dst = dst_addr;

}

void run(struct pcap_args args)
{
	struct ip ip;
	struct ip6_hdr ip6;
	struct tcphdr tcp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;

	unsigned char *packet;
	packet = (unsigned char *)malloc(60);
    if (args.type == 4) {
	    set_ip_header(&ip, args.dst_addr.in4, args.src_addr.in4);
	    memcpy(packet, &ip, sizeof(ip));
    }
    else {
	    set_ip6_header(&ip6, args.dst_addr.in6, args.src_addr.in6);
	    memcpy(packet, &ip6, sizeof(ip6));
    }

	tcp.th_sport = htons(33334);
	tcp.th_dport = htons(args.dst_port);
	tcp.th_seq = htonl(0x10);
	tcp.th_off = sizeof(struct tcphdr) / 4;
	tcp.th_flags = TH_SYN;
	tcp.th_win = htons(2048);
	tcp.th_sum = 0;
	tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (uint16_t *)&tcp, sizeof(tcp));
	memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));
	
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		exit(1);
	}
}


void raw_packet_receiver(unsigned char *udata, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    struct ip *ip;
    struct tcphdr *tcp;
    unsigned char *ptr;
    int l1_len = (int)udata;
    int s_seq;

    ip = (struct ip *)(packet + l1_len);
    tcp = (struct tcphdr *)(packet + l1_len + sizeof(struct ip));

    printf("%d\n", l1_len);

    printf("a packet came, ack is: %d\n", ntohl(tcp->th_ack));
    printf("a packet came, seq is: %u\n", ntohl(tcp->th_seq));
    if (tcp->th_flags & TH_RST) {
        printf("Holy shit I found the reset!\n");
    }
    if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
        printf("Saw SYN/ACK\n");
    }
    s_seq = ntohl(tcp->th_seq);

    sleep(1);
    printf("done sleeping 1 second\n");
}

void *pth_capture_run(void *arg)
{
    pcap_t *pd;
    struct pcap_args *foo = (struct pcap_args *)arg;
    char *filter_fmt = "port %d and ip";
    char *filter = malloc(sizeof(filter_fmt)+5);
    int len = snprintf(NULL, 0, filter_fmt, (int)foo->dst_port);
    snprintf(filter, len+1, filter_fmt, (int)foo->dst_port);
    printf("The filter expression: %s\n", filter);
    char *dev = "en0";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program  fprog;                  /* Filter Program   */
    long int dl = 0, dl_len = 0;

    if ((pd = pcap_open_live(dev, 1514, 1, 500, errbuf)) == NULL) {
        fprintf(stderr, "cannot open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    pcap_compile(pd, &fprog, filter, 0, netp);
    if (pcap_setfilter(pd, &fprog) == -1) {
        fprintf(stderr, "cannot set pcap filter %s: %s\n", filter, errbuf);
        exit(1);
    }
    pcap_freecode(&fprog);
    dl = pcap_datalink(pd);

    switch(dl) {
        case 1:
            dl_len = 14;
            break;
        default:
            dl_len = 4;
            break;
    }

    if (pcap_loop(pd, 2, raw_packet_receiver, (unsigned char *)dl_len) < 0) {
        fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(pd));
        exit(1);
    }
    void* ret = NULL;
    return ret;
}


int main(int argc, char **argv) {

    if (argc < 4) {
        printf("usage:\n\t%s <dst_addr> <src_addr> <dst_port>\n", argv[0]);
        exit(1);
    }
    int addrtest6=0, addrtest4=0;
    pthread_t tid_pr;
    uint16_t dst_port = (uint16_t)atoi(argv[3]);
    struct in6_addr src_addr6, dst_addr6;
    struct in_addr src_addr4, dst_addr4;
    if ((addrtest6 = inet_pton (AF_INET6, argv[1], &dst_addr6)) != 1) {
        addrtest6 = 0;
        if ((addrtest4 = inet_pton (AF_INET, argv[1], &dst_addr4)) != 1) {
            fprintf (stderr, "inet_pton() failed: %s\n", strerror (addrtest4));
            exit (EXIT_FAILURE);
        }
    }
    if ((addrtest6 = inet_pton (AF_INET6, argv[2], &src_addr6)) != 1) {
        addrtest6 = 0;
        if ((addrtest4 = inet_pton (AF_INET, argv[2], &src_addr4)) != 1) {
            fprintf(stderr, "inet_pton() failed: %s\n", strerror (addrtest4));
            exit (EXIT_FAILURE);
        }
    }
    struct pcap_args args;
    if (addrtest4 && addrtest6) {
        fprintf(stderr, "inet_ptons() believes the source and dest addresses are incompatable");
        exit(1);
    }
    else if (addrtest6) {
        args.src_addr.in6 = src_addr6;
        args.dst_addr.in6 = dst_addr6;
        args.type = 6;
        args.dst_port=dst_port;
    }
    else {
        args.src_addr.in4 = src_addr4;
        args.dst_addr.in4 = dst_addr4;
        args.type = 4;
        args.dst_port=dst_port;
    }

    void *args_ptr = (void *)&args;

    if (pthread_create(&tid_pr, NULL, pth_capture_run, args_ptr) != 0) {
        fprintf(stderr, "cannot create raw packet reader: %s\n", strerror(errno));
        exit(1);
    }
    printf("raw packet reader created, waiting 1 seconds for packet reader thread to settle down...\n");
    sleep(1);
    run(args);

    pthread_join(tid_pr, NULL);
    return 0;
}

/*
int main(int argc, char **argv)
{
	run(NULL);	
	return 0;
}
*/

