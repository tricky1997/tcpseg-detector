#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <pcap.h>
#include <dnet.h>
#include <dnet/ip.h>
#include <err.h>
#include <semaphore.h>

pthread_mutex_t main_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t main_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t thread_cond = PTHREAD_COND_INITIALIZER;
sem_t main_sem;
sem_t thread_sem;
int sockfd = 0;

static void tell_main()
{
	do {
	    sem_post(&main_sem);
	} while (0);
}

static void tell_thread()
{
	do {
	  sem_post(&thread_sem);
	} while (0);
}
static void wait_main()
{
	do {
	    sem_wait(&thread_sem);
	} while(0);
}
static void wait_thread()
{
	do {
	    sem_wait(&main_sem);
	} while(0);
}
/*
 * 0~4  1111
 * 6~10 2222
 * 2~8  333333
 */
#define DATA1 "11111111"
#define DATA2 "22222222"
#define DATA3 "33333333"

#define FAVOR_OLD    "1111332222"
#define FAVOR_NEW    "1133333322"
#define FAVOR_BEFORE "1133332222"
#define FAVOR_AFTER  "1111333322"

struct send_pkt{
	const char *data;
	unsigned int data_len;
	unsigned int seq;
	unsigned char flags;
	unsigned int  ack;
};

unsigned int ip_seq = 12343433;
unsigned int tcp_seq = 0;
unsigned int dst_seq = 0;

/* settings */
/* libpcap needs local */
int local = 0;
/* libdnet needs addrs */
const char *dst = "127.0.0.1";
const char *src = "127.0.0.1";
struct addr s_addr;
struct addr d_addr;

int sport = 0;
int dport = 10000;

static int build_buf(const struct send_pkt *pkt, char *buf, unsigned int len)
{
	struct ip_hdr *ip_hdr = (struct ip_hdr *)buf;
	struct tcp_hdr *tcp_hdr = (struct tcp_hdr *)(ip_hdr + 1);
	char *p = (char *)(tcp_hdr + 1);

	assert((char *)tcp_hdr == ((char *)ip_hdr + IP_HDR_LEN));
	assert(len > 40 + pkt->data_len);
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(pkt->data_len + TCP_HDR_LEN + IP_HDR_LEN);
	ip_hdr->ip_id = htons(ip_seq++);
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = IP_TTL_MAX;
	ip_hdr->ip_p = IP_PROTO_TCP;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src = s_addr.addr_ip;
	ip_hdr->ip_dst = d_addr.addr_ip;

	tcp_pack_hdr(tcp_hdr, sport, dport, tcp_seq + pkt->seq, pkt->ack, pkt->flags, 2048, 0);

	memcpy(p, pkt->data, pkt->data_len);

	return ntohs(ip_hdr->ip_len);
}

static void raw_send(const struct send_pkt *s, unsigned int len)
{
	static char ip_buf[2048];
	static ip_t *ip_p = NULL;
	int n;
	unsigned int i;

	if (!ip_p) {
		ip_p = ip_open();
		if (!ip_p)
			err(1, "ip_open");
	}
	for (i = 0 ; i < len; ++i) {
		memset(ip_buf, 0, sizeof(ip_buf));
		n = build_buf(&s[i], ip_buf, sizeof(ip_buf));
		ip_checksum(ip_buf, n);
		ip_send(ip_p, ip_buf, n);
	}

	return;
}

static void do_send()
{
	/* SYN is 0 */
	const struct send_pkt send_pkts[] = {
		{DATA1, 4, 0, TH_ACK, dst_seq},
		{DATA2, 4, 6, TH_ACK, dst_seq},
		{DATA3, 6, 2, TH_ACK, dst_seq},
	};

	raw_send(send_pkts, sizeof(send_pkts)/sizeof(send_pkts[0]));

	return;
}

static int socket_connect()
{
	int sockfd, n;
	const int on = 1;
	struct sockaddr_in addr;
	struct linger l = {
		.l_onoff = 1,
		.l_linger = 0,
	};

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
		err(1, "socket");

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) == -1)
		err(1, "linger");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	addr.sin_addr.s_addr = inet_addr(dst);
	addr.sin_port = htons(dport);

	n = connect(sockfd, (const struct sockaddr*)&addr, sizeof(addr));
	if (n == -1)
		err(1, "connect");

	return sockfd;
}

static void recv_cb(u_char *usr, const struct pcap_pkthdr *h,
		    const u_char *bytes)
{
	static struct send_pkt pkt = {
		.data = "",
		.data_len = 0,
		.seq = 10,
		.flags = TH_ACK,
		.ack = 0,
	};
	pcap_t *handle = (pcap_t*)usr;
	const struct eth_hdr *eth_hdr;
	const struct ip_hdr *ip_hdr;
	const struct tcp_hdr *tcp_hdr;
	const unsigned char *payload;
	int n;
	int ip_hdr_len;
	int tcp_hdr_len;
	static int c = 0;
	static unsigned int len = 0;
	static char buf[2048] = {0};

	(void)h;
	if (!bytes)
		return;

	eth_hdr = (const struct eth_hdr*)bytes;
	ip_hdr = (const struct ip_hdr*)(eth_hdr + 1);
	ip_hdr_len = ip_hdr->ip_hl * 4;
	tcp_hdr = (const struct tcp_hdr *)((char *)ip_hdr + ip_hdr_len);
	tcp_hdr_len = tcp_hdr->th_off * 4;
	payload = (const unsigned char *)((char *)tcp_hdr + tcp_hdr_len);

	n = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
	if (n == 0)
		/* recv an ack */
		return;

	memcpy(buf + len, payload, n);
	len += n;
	/* send an ack */
	pkt.ack = ntohl(tcp_hdr->th_seq) + n;
	raw_send(&pkt, 1);

	/* XXX wait until 8 or 10 
	 * some system may ignore the packets out of sequence 
	 * or not send 2222
	 */
	if (len < strlen(FAVOR_OLD) - 2)
		return;

	if (strncmp(buf, FAVOR_OLD, len) == 0) {
		printf("old\n");
		fflush(stdout);
	} else if (strncmp(buf, FAVOR_NEW, len) == 0) {
		printf("new\n");
		fflush(stdout);
	} else if (strncmp(buf, FAVOR_BEFORE, len) == 0) {
		printf("before\n");
		fflush(stdout);
		  } else if (strncmp(buf, FAVOR_AFTER, len) == 0) {
		printf("after\n");
		fflush(stdout);
	} else if (len >= 10) {
		printf("Unknown %s\n", buf);
		fflush(stdout);
	} else {
		printf("\nrecved %s. try to read again\nrecv:", buf);
		fflush(stdout);
	}

	if (++c > 10) {
		warnx("tried too many times. exit...");
	}

	pcap_breakloop(handle);
}

/* prepare addr for libdnet */
static void prepare(int sockfd)
{
	struct sockaddr addr;
	unsigned int len = sizeof(struct sockaddr);
	struct sockaddr_in *addr_in;

	if (-1 == getsockname(sockfd, &addr, &len))
		err(1, "getsockname");
	addr_in = (struct sockaddr_in *)&addr;
	src = inet_ntoa(addr_in->sin_addr);
	sport = ntohs(addr_in->sin_port);
	printf("local addr: %s:%d\n", src, sport);
	/* for libdnet */
	addr_aton(src, &s_addr);
	addr_aton(dst, &d_addr);
	return;
}

static void *pcap_thread(void *arg)
{
	char errbuf[2048];	
	const char *dev = NULL;
	pcap_t *handle;
	struct bpf_program fp;
	char rule[2048];
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;

	const unsigned char *data = NULL;
	const struct eth_hdr *eth_hdr;
	const struct ip_hdr *ip_hdr;
	const struct tcp_hdr *tcp_hdr;

	int n;

	(void)arg;
	if (local)
		dev = "lo";
	else
		dev = "eth0";
	  n = snprintf(rule, sizeof(rule), "src port %d", dport);
	rule[n] = 0;
	arg = NULL;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
		err(1, "pcap_lookupnet");
	handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
	if (!handle) {
		err(1, "pcap_open_live:%s", errbuf);
	}
	if (pcap_compile(handle, &fp, rule, 0, net) == -1)
		err(1, "pcap_compile %s:%s", rule, errbuf);
	if (pcap_setfilter(handle, &fp) == -1)
		err(1, "pcap_setfilter:%s", pcap_geterr(handle));

	printf("initializing...");
	fflush(stdout);
	sleep(1);

	sockfd = socket_connect();
	prepare(sockfd);
	while (!data)
		data = pcap_next(handle, &header);

	eth_hdr = (const struct eth_hdr*)data;
	ip_hdr = (const struct ip_hdr *)(eth_hdr+1);
	tcp_hdr = (const struct tcp_hdr *)(ip_hdr+1);

	tcp_seq = ntohl(tcp_hdr->th_ack);
	dst_seq = ntohl(tcp_hdr->th_seq) + 1;
	tell_main();

	printf("recv:");
	fflush(stdout);

	wait_main();
	pcap_loop(handle, 0, recv_cb, (u_char*)handle);

	pcap_freecode(&fp);
	pcap_close(handle);
	close(sockfd);
	pthread_exit(NULL);
}

static void usage()
{
	warnx("[s src_port][d dst_port] ip");
}

static void sigalrm(int a)
{
	/* some host send back 11113333 without the final 22
	/* and don't ack it. so we just wait for 10s
	 */
        (void)a;
	errx(0, "\n10s passed, dst seems not to support out of order recv.\n");
}

int main(int argc, char **argv)
{
	pthread_t tid;
	int opt;

	sem_init(&main_sem, 0, 0);
	sem_init(&thread_sem, 0, 0);
	while ((opt = getopt(argc, argv, "hs:d:")) != -1) {
		switch (opt){
		case 'h':
			usage();
			exit(0);
		case 'l':
			local = 1;
			break;
		case 's':
			sport = atoi(optarg);
		case 'd':
			dport = atoi(optarg);
			break;
		default:
			usage();
			exit(0);
		}
	}
	if (optind != (argc - 1)) {
		usage();
		exit(0);
	}
	dst = argv[optind];
	/* prepare local for libpcap */
	if (strcmp(dst, "127.0.0.1") == 0 || strcmp(src, dst) == 0)
		local = 1;

	signal(SIGALRM, sigalrm);
	alarm(10);
	pthread_create(&tid, NULL, pcap_thread, NULL);

	/* wait init ack num */
	while (tcp_seq == 0) {
		wait_thread();
	}

	/* when do_send OK, wait analyse */
	do_send();
	tell_thread();

	pthread_join(tid, NULL);
	exit(0);
}
