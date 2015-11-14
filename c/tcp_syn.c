/*
        TCP RAW SOCKET EXAMPLE
        Murat Balaban [murat@enderunix.org]
        You should've received a copy of BSD-style license with the tarball.
        See COPYING for copyright info.
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr tcp;
};

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

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


unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_tcp buf;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(len);
	memcpy(&(buf.tcp), addr, len);
	return in_cksum((unsigned short *)&buf, 12 + len);
}



int run(void *arg)
{
	struct ip ip;
	struct tcphdr tcp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;


	u_char *packet;
	packet = (u_char *)malloc(60);
	
	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = sizeof(struct ip) + sizeof(struct tcphdr); 
	ip.ip_id = htons(12830);
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_TCP;
	ip.ip_sum = 0x0;
	ip.ip_src.s_addr = inet_addr("127.0.0.1");
	ip.ip_dst.s_addr = inet_addr("127.0.0.1");
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
	memcpy(packet, &ip, sizeof(ip));

	tcp.th_sport = htons(33334);
	tcp.th_dport = htons(33333);
	tcp.th_seq = htonl(0x10);
	tcp.th_off = sizeof(struct tcphdr) / 4;
	tcp.th_flags = TH_SYN;
	tcp.th_win = htons(2048);
	tcp.th_sum = 0;
	tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
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
	return sd;
}


void raw_packet_receiver(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *ip;
    struct tcphdr *tcp;
    u_char *ptr;
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
    s_seq = ntohl(tcp->th_seq);

    sleep(1);
    printf("done sleeping 1 second\n");
}

void *pth_capture_run(void *arg)
{
    pcap_t *pd;
    char *filter = "dst host 127.0.0.1 and ip";
    char *dev = "lo0";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program  fprog;                  /* Filter Program   */
    int dl = 0, dl_len = 0;

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

    if (pcap_loop(pd, 2, raw_packet_receiver, (u_char *)dl_len) < 0) {
        fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(pd));
        exit(1);
    }
}

int main(int argc, char **argv)
{
    pthread_t tid_pr;

    if (pthread_create(&tid_pr, NULL, pth_capture_run, NULL) != 0) {
        fprintf(stderr, "cannot create raw packet reader: %s\n", strerror(errno));
        exit(1);
    }
    printf("raw packet reader created, waiting 1 seconds for packet reader thread to settle down...\n");
    sleep(1);

    int sd = run(NULL);

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

