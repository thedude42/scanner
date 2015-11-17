#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include <netdb.h>
#include <sys/types.h>        // uint8_t, uint16_t
#include <sys/socket.h>       // socket()
#include <netinet/in.h>       // IPPROTO_UDP
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/udp.h>      // struct udphdr
#include <netinet/ip_icmp.h>  // struct icmphdr
#include <netinet/icmp6.h>    // struct icmp6_hdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()

#include <pcap/pcap.h>

#define IPPAYLOADLEN 16 // UDP header plus 8 byte payload
#define ALL_PORTS 65535

static int SCANNED[ALL_PORTS];

struct psd4_udp {
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short udp_len;
    struct udphdr udp;
};

struct psd6_udp {
    struct in6_addr src;
    struct in6_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short udp_len;
    struct udphdr udp;
};

union generic_addr {
    struct in_addr in4;
    struct in6_addr in6;
};

struct scan_args {
    union generic_addr dst_addr;
    union generic_addr src_addr;
    int type;
    uint16_t start_port;
    uint16_t end_port;
    char *iface;
};

struct pcap_args {
    char *dst_addr; 
    int type;
    char *dev;
    int num_ports;
};

uint16_t
in_cksum(uint16_t *buffptr, int len) {
	int nleft=len, sum=0;
	uint16_t *w=buffptr, answer=0;

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

void
set_ip_header(struct ip *ip, struct in_addr dst_addr, struct in_addr src_addr) {
	ip->ip_hl = 0x5;
	ip->ip_v = 0x4;
	ip->ip_tos = 0x0;
	ip->ip_len = sizeof(struct ip) + IPPAYLOADLEN; 
	ip->ip_id = htons(12830);
	ip->ip_off = 0x0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0x0;
	ip->ip_src = src_addr;
	ip->ip_dst = dst_addr;
	ip->ip_sum = in_cksum((uint16_t *)&ip, sizeof(ip));
}

void
set_ip6_header(struct ip6_hdr *ip6, struct in6_addr dst_addr, struct in6_addr src_addr) {
    ip6->ip6_flow = htonl(0x42414142);
    ip6->ip6_plen = htons(IPPAYLOADLEN); // payload of one udp header + payload
    ip6->ip6_nxt = IPPROTO_UDP;
    ip6->ip6_hops = 0xFF;
    ip6->ip6_src = src_addr;
    ip6->ip6_dst = dst_addr;

}

uint16_t
in4_cksum_udp(int src, int dst, unsigned short *addr, int len) {
    struct psd4_udp buf;

    memset(&buf, 0, sizeof(buf));
    buf.src.s_addr = src;
    buf.dst.s_addr = dst;
    buf.pad = 0;
    buf.proto = IPPROTO_UDP;
    buf.udp_len = htons(len);
    memcpy(&(buf.udp), addr, len);
    return in_cksum((unsigned short *)&buf, 12 + len);
}

void
set_udp_header(struct udphdr *udphdr, uint16_t dst_port) {
    udphdr->uh_sport = htons(0x4141);
    udphdr->uh_dport = htons(dst_port);
    udphdr->uh_ulen = htons(IPPAYLOADLEN);
    udphdr->uh_sum = 0;
}

void
build_udp4(unsigned char *pkt,
                struct sockaddr_in *sockaddr,
                int sockaddrlen,
                struct ip *ip,
                int iplen,
                struct udphdr *udp,
                int udplen,
                char *data,
                int datalen) {
    memcpy(pkt+iplen, udp, udplen);
    memcpy(pkt+iplen+udplen, data, datalen);
    printf("sending ipv4 packet\n");
    memset(sockaddr, 0, sockaddrlen);
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = ip->ip_dst.s_addr;
}

void
build_udp6(unsigned char *pkt,
                struct sockaddr_in6 *sockaddr6,
                int sockaddrlen,
                struct ip6_hdr *ip6,
                int iplen,
                struct udphdr *udp,
                int udplen,
                char *data,
                int datalen) {
    memcpy(pkt+iplen, udp, udplen);
    memcpy(pkt+iplen+udplen, data, datalen);
    printf("sending ipv6 packet\n");
    memset(sockaddr6, 0, sockaddrlen);
    sockaddr6->sin6_family = AF_INET6;
    sockaddr6->sin6_addr = ip6->ip6_dst;
}

void
pcap_callback(unsigned char *udata, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip;
    struct ip6_hdr *ip6;
    struct udphdr *udp;
    struct icmp *icmp;
    struct icmp6_hdr *icmp6;
    int dl_header_len = (int)udata;
    int isclosed=0;

    ip = (struct ip *)(packet + dl_header_len);
    printf("CALLBACK\n");
    if (ip->ip_v == 0x6)
        ip6 = (struct ip6_hdr *)(packet + dl_header_len);
    if (((ip->ip_v == 0x4) && (ip->ip_p == 1)) ||
       ((ip->ip_v == 0x6) && (ip6->ip6_nxt == 58))) { // ICMP
        icmp = (struct icmp *)(packet + dl_header_len + sizeof(struct ip));
        if (ip->ip_v == 0x6) {
            icmp6 = (struct icmp6_hdr *)(packet + dl_header_len + sizeof(struct ip6_hdr));
          //  if (icmp6->icmp6_type == 0x1 && icmp6->icmp6_code == 0x4) {
                isclosed = 1;
          //  }
          //  else {
          //      fprintf(stderr, "ICMP6 type not \"dst port unreachable\"\n");
          //      return;
          //  }
        }
        else {
            if (icmp->icmp_type == 0x3 && icmp->icmp_code == 0x3) {
                isclosed = 1;
            }
            else {
                fprintf(stderr, "ICMP type not \"dst port unreachable\"\n");
                return;
            }
        }
    }
    else {
        udp = (struct udphdr *)(packet + dl_header_len + sizeof(struct ip));
    }
    if (isclosed) {
        if (ip->ip_v == 0x4) {
            printf("CLOSED: PORT %s\n", (char *) (&(icmp->icmp_dun.id_data)+20+8));
            SCANNED
        }
        else {

            printf("CLOSED: PORT %s\n", (char *) (&(icmp6->icmp6_dataun)+40+8));
        }
    }
    usleep(10000);
    printf("done sleeping 10k useconds\n");
}

void
send_packets(struct scan_args *args, useconds_t waittime) {
    struct ip ip;
    struct ip6_hdr ip6;
    struct udphdr udp;
    int sd;
    char data[8];
    memset(data, 0, 8);
    const int on = 1;
    struct sockaddr_in sin;
    struct sockaddr_in6  sin6;
    unsigned char *packet;

    if (args->type == 4)
        packet = (unsigned char *)malloc(20+IPPAYLOADLEN);
    else
        packet = (unsigned char *)malloc(40+IPPAYLOADLEN);
    //set base ip/ip6 header for use for the given dest address
    if (args->type == 4) {
        set_ip_header(&ip, args->dst_addr.in4, args->src_addr.in4);
        memcpy(packet, &ip, sizeof(ip));
    }
    else {
        set_ip6_header(&ip6, args->dst_addr.in6, args->src_addr.in6);
        memcpy(packet, &ip6, sizeof(ip6));
    } 
    for (int i = args->start_port; i <= args->end_port; ++i) {
        sprintf(data, "%d", i);
        if ((args->type == 4) && 
          ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) ) {
            perror("raw socket4");
            exit(1);
        }
        else if ((args->type == 6) &&
          ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) ) {
            perror("raw socket6");
            exit(1);
        }
        if ((args->type == 4) &&
          (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)) {
            perror("setsockopt");
            exit(1);
        }
        //build udp packet
        set_udp_header(&udp, i);
        if (args->type == 4) {
            build_udp4(packet, &sin, sizeof(sin), &ip, sizeof(ip), 
                       &udp, sizeof(udp), data, sizeof(data));
            //hard-coded 54 based on 6+6+2 (ethernet) +20 (ip) +8+8 (udp+data)
            if (sendto(sd, packet, 54, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)  {
                perror("sendto");
                exit(1);
            }
        }
        else {
            build_udp6(packet, &sin6, sizeof(sin6), &ip6, sizeof(ip6), &udp,
                       sizeof(udp), data, sizeof(data));
            //hard coded based on 40 (ip) +8+8 (udp+data), no ethernet since no setsockopt call
            if (sendto(sd, packet, 56, 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0)  {
                perror("sendto");
                exit(1);
            }
        }
        sleep(1);
    }
}

void *
pth_capture_run(void *inargs) {
    struct pcap_args *args = (struct pcap_args *)inargs;
    pcap_t *pd;
    char *filter_fmt;
    if (args->type == 4)
        filter_fmt = "src %s and (udp or icmp)";
    else
        filter_fmt = "src %s and (udp or icmp6)";
    char *filter = malloc(sizeof(filter_fmt)+5);
    int len = snprintf(NULL, 0, filter_fmt, args->dst_addr);
    snprintf(filter, len+1, filter_fmt, args->dst_addr);
    printf("The filter expression: %s\n", filter);
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program  fprog;                  /* Filter Program   */
    long int dl = 0, dl_len = 0;

    if ((pd = pcap_open_live(args->dev, 1514, 1, 500, errbuf)) == NULL) {
        fprintf(stderr, "cannot open device %s: %s\n", args->dev, errbuf);
        exit(1);
    }

    pcap_lookupnet(args->dev, &netp, &maskp, errbuf);
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
            dl_len = 4; //loopback frame on Darwin
            break;
    }

    if (pcap_loop(pd, args->num_ports, pcap_callback, (unsigned char *)dl_len) < 0) {
        fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(pd));
        exit(1);
    }
    // getting rid of compiler warnings
    void* ret = NULL;
    return ret;
}

void
usage(char *exec_name) {
    printf("usage:\n\t%s <dst_addr> <src_addr> <start_port> [ end_port ] <iface>\n", exec_name);
}

int
main(int argc, char **argv) {
    if (argc < 5) {
        usage(argv[0]);
        exit(1);
    }
    int addrtype=0;
    pthread_t tid_pr;
    char *iface;
    uint16_t start_port = (uint16_t)atoi(argv[3]);
    uint16_t end_port = (uint16_t)atoi(argv[4]) ? (uint16_t)atoi(argv[4]) : start_port;
    if (start_port == end_port) 
        iface = argv[4];
    else if (argc == 6) {
        iface = argv[5];
    }
    else {
        printf("Ambiguous arguments, require at most 5, at least 4\n");
        usage(argv[0]);
        exit(1);
    }
    struct in6_addr src_addr6, dst_addr6;
    struct in_addr src_addr4, dst_addr4;
    // determine if we got an ipv4 or ipv6 address
    if ((inet_pton(AF_INET6, argv[1], &dst_addr6) != 1) || 
        (inet_pton(AF_INET6, argv[2], &src_addr6) != 1)) {
        if ((inet_pton(AF_INET, argv[1], &dst_addr4) != 1) || 
            (inet_pton(AF_INET, argv[2], &src_addr4) != 1)) {
            fprintf (stderr, "inet_pton() failed to convert src and dst addresses to same version of ip addresses\n");
            exit (EXIT_FAILURE);
        }
        else {
            addrtype = 4;
        }
    }
    else {
        addrtype = 6;
    }
    printf("addr type is %d\n", addrtype);
    // set up arguments struct for use with the rest of the operations
    struct scan_args args = {
        .type=addrtype,
        .iface=iface,
        .start_port=start_port,
        .end_port=end_port
    };
    if (addrtype == 4) {
        args.dst_addr.in4 = dst_addr4;
        args.src_addr.in4 = src_addr4;
    }
    else {
        args.dst_addr.in6 = dst_addr6;
        args.src_addr.in6 = src_addr6;
    }
    struct pcap_args pargs = {
        .dst_addr=argv[1],
        .type=args.type,
        .dev=iface,
        .num_ports=args.end_port-args.start_port+1
    };

    if (pthread_create(&tid_pr, NULL, pth_capture_run, (void *)&pargs) != 0) {
        fprintf(stderr, "cannot create raw packet reader: %s\n", strerror(errno));
        exit(1);
    }
    printf("raw packet reader created, waiting 1 seconds for packet reader thread to settle down...\n");
    sleep(1);

    send_packets(&args, 1000000);
    pthread_join(tid_pr, NULL);
}
