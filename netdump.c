/** Author: Sebastian Kazun
 * Netid: smkazun
 * Spring 2020
 * 4/30/20
 */

#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

//Added variables
int num_ip_packets, num_arp_packets, num_icmp_packets, num_tcp_packets, num_dns_packets = 0;

//program 3 additions
int num_smtp_packets, num_pop_packets, num_imap_packets, num_http_packets = 0;

void print_ip_header(const u_char *p);
void print_arp_header(const u_char *p);
void print_tcp_header(const u_char *p);
void print_icmp_header(const u_char *p);

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	//TODO
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
			//added
			(void) fprintf(stderr, "%d packets were IPv4\n", num_ip_packets);
			(void) fprintf(stderr, "%d packets were ARP\n", num_arp_packets);
			(void) fprintf(stderr, "%d packets were ICMP\n", num_icmp_packets);
			(void) fprintf(stderr, "%d packets were TCP\n", num_tcp_packets);
			(void) fprintf(stderr, "%d packets were DNS\n", num_dns_packets);
			(void) fprintf(stderr, "%d packets were SMTP\n", num_smtp_packets);
			(void) fprintf(stderr, "%d packets were POP\n", num_pop_packets);
			(void) fprintf(stderr, "%d packets were IMAP\n", num_imap_packets);
			(void) fprintf(stderr, "%d packets were HTTP\n", num_http_packets);
		}
	}
	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}


void print_arp_header(const u_char *p)
{
	printf("\t------------START Decoding ARP Header------------\n");
	uint16_t hardware_type = (p[14] << 8) + p[15];
	uint16_t protocol_type = (p[16] << 8) + p[17];
	uint8_t hardware_len = p[18];
	uint8_t protocol_len = p[19];
	uint16_t operation = (p[20] << 8) + p[21]; 

	printf("\tHardware Type: %u\n", hardware_type);
	printf("\tProtocol Type: 0x%x\n", protocol_type);
	printf("\tHardware Length: %u\n", hardware_len);
	printf("\tProtocol Length: %u\n", protocol_len);
	printf("\tOperation: %u (%s)\n", operation, operation == 1 ? "Arp Request" : "ARP Reply");

	printf("\tSender Hardware Address = %02X:%02x:%02X:%02X:%02X:%02X\n", p[22], p[23], p[24], p[25], p[26], p[27]);
	printf("\tSender IP Address = %03d.%03d.%03d.%03d\n", p[28], p[29], p[30], p[31]);
	printf("\tTarget Hardware Address = %02X:%02x:%02X:%02X:%02X:%02X\n", p[32], p[33], p[34], p[35], p[36], p[37]);
	printf("\tTarget IP Address = %03d.%03d.%03d.%03d\n", p[38], p[39], p[40], p[41]);

	printf("\t------------END Decoding------------\n");
}

void print_ip_header(const u_char *p)
{
	printf("\t------------START Decoding IP Header------------\n");
	uint8_t version = p[14] >> 4; //get first 4 bits //or (p[14] & 0xF0) >>4
	uint8_t header_len = (p[14] & 0x0f) * 4; //gives number 0-15  (0000 1111) bottom 4 bits of a byte
	uint8_t service_type = p[15];
	uint16_t len = (p[16] << 8) + p[17]; //16 bits
	uint16_t id = (p[18] << 8) + p[19]; 
	uint8_t flags = p[20] >> 5; //only care about first 3 bits
	uint16_t offset = ((p[20] << 8) & 0x1f) + p[21];
	uint8_t ttl = p[22];
	uint8_t protocol = p[23];
	uint16_t checksum = (p[24] << 8) + p[25];

	printf("\tVersion number = %u\n", version);
	printf("\tHeader Length = %u bytes\n", header_len);
	printf("\tType of Service = %u\n", service_type);
	printf("\tTotal Length = %u bytes\n", len);
	printf("\tID = 0x%x\n", id);							
	printf("\tFlags = %u%u%u\n", (flags >> 2), (flags >> 1) & 0x01, (flags & 0x01));
	printf("\t\t%s", ((flags >> 1) & 0x01) ? "D Flag - Don't Fragment\n" : "Fragment\n");
	
	printf("\tOffset = %u bytes\n", offset);
	printf("\tTime To Live = %u\n", ttl);
	printf("\tProtocol = %u", protocol);
	if(protocol == 1)
	{
		printf(" -> ICMP\n");
	}	
	else if(protocol == 6)
	{
		printf(" -> TCP\n");
	}
	else
	{
		printf(" -> Not Handled\n");
	}
	
	printf("\tChecksum = 0x%x\n", checksum);
	printf("\tSource IP Address = %d.%d.%d.%d\n", p[26], p[27], p[28], p[29]);
	printf("\tDestination IP Address = %d.%d.%d.%d\n", p[30], p[31], p[32], p[33]);
	
	printf("\t------------END Decoding------------\n");
	
	switch(protocol)
	{
		//ICMP
		case 1:
			print_icmp_header(p);
			num_icmp_packets++;
			break;
		//TCP
		case 6:
			print_tcp_header(p);
			num_tcp_packets++;
			break;
		//UDP to get dns packets
		case 17:
			
			uint8_t udp_port = (p[header_len + 2] << 8) + p[header_len + 3];
			if(udp_port == 53)
				num_dns_packets++;
			break;

		default:
			printf("Protocol %u not supported\n", protocol);
	}
}

void print_icmp_header(const u_char *p)
{
	printf("\t\t------------START Decoding ICMP Header------------\n");

	uint8_t type = p[34];
	uint8_t code = p[35];
	uint16_t checksum = (p[36] << 8) + p[37];
	uint32_t parameter;
	uint16_t id;
	uint16_t seq_num;
	uint64_t info;

	printf("\t\tType = %d\n", type);
	printf("\t\tCode = %d\n", code);
	printf("\t\tChecksum = 0x%x\n", checksum);

	//split parameter into id and seq_no
	if(type == 0 && code == 0)
	{
		printf("\t\tEcho Reply\n");
		id = (p[38] << 8) + p[39];
		seq_num = (p[40] << 8) + p[41];

		printf("\t\tId = %x\n", id);
		printf("\t\tSequence Number = %x\n", seq_num);
	}
	else if(type == 8 && code == 0)
	{
		printf("\t\tEcho Request\n");
		id = (p[38] << 8) + p[39];
		seq_num = (p[40] << 8) + p[41];

		printf("\t\tId = %x\n", id);
		printf("\t\tSequence Number = %x\n", seq_num);
	}
	else if(type == 8 && code == 0)
	{
		printf("\t\tEcho Request\n");
		id = (p[38] << 8) + p[39];
		seq_num = (p[40] << 8) + p[41];

		printf("\t\tId = %x\n", id);
		printf("\t\tSequence Number = %x\n", seq_num);
	}
	else if(type == 13 && code == 0)
	{
		printf("\t\tTimestamp Request\n");
		id = (p[38] << 8) + p[39];
		seq_num = (p[40] << 8) + p[41];

		printf("\t\tId = %x\n", id);
		printf("\t\tSequence Number = %x\n", seq_num);
	}
	else if(type == 14 && code == 0)
	{
		printf("\t\tTimestamp Reply\n");
		id = (p[38] << 8) + p[39];
		seq_num = (p[40] << 8) + p[41];

		printf("\t\tId = %x\n", id);
		printf("\t\tSequence Number = %x\n", seq_num);
	}
	else if(type == 3 && (code > 0 && code < 16))
	{
		printf("\t\tDestination Unreachable\n");
		parameter = (p[38] << 24) + (p[39] << 16) + (p[40] << 8) + p[41];
		printf("\t\tParameter = %x\n", parameter);
	}
	else if(type == 11 && (code == 0 || code == 1))
	{
		printf("Time Exceeded\n");
		parameter = (p[38] << 24) + (p[39] << 16) + (p[40] << 8) + p[41];
		printf("\t\tParameter = %x\n", parameter);
	}
	else if(type == 5 && (code >= 0 && code < 4))
	{
		printf("IP Address\n");
	}
	
	//payload
	info = (p[42] << 64) + (p[43] << 56) + (p[44] << 48) + (p[45] << 32) + (p[36] << 24) + (p[47] << 16) + (p[48] << 8) + p[49];
	printf("Info: %x", info);

}

void print_tcp_header(const u_char *p)
{
	printf("\t\t------------START Decoding TCP Header------------\n");
	uint16_t src_port = (p[34] << 8) + p[35];
	uint16_t dest_port = (p[36] << 8) + p[37];
	uint32_t seq_number = (p[38] << 24) + (p[39] << 16) + (p[40] << 8) + p[41];
	uint32_t ack_number = (p[42] << 24) + (p[43] << 16) + (p[44] << 8) + p[45];
	uint8_t header_len = (p[46] >> 4) * 4; //(4 bits) //or &0xF0 instead of >> 4
	uint8_t reserved = ((p[46] * 0x0f) << 2) + (p[47] >> 6); //6 bits //TODO? (p[46] & 0x3F) >> 2
	uint8_t flags = p[47] & 0x3f; //6bits
	uint16_t window_size = (p[48] << 8) + p[49];
	uint16_t checksum = (p[50] << 8) + p[51];
	uint16_t urgent_ptr = (p[52] << 8) + p[53];
	uint64_t options;

	
	printf("\t\tSource Port = %d\n", src_port);
	printf("\t\tDestination Port = %d\n", dest_port);
	printf("\t\tSequence Number = 0x%x\n", seq_number);
	printf("\t\tAcknowledgement Number = 0x%x\n", ack_number);
	printf("\t\tHeader length = %d bytes\n", header_len);
	printf("\t\tReserved = %d\n", reserved);

	printf("\t\tFlags = %u%u%u%u%u%u\n", (flags >> 5), ((flags >> 4) & 0x01), ((flags >> 3) & 0x01), ((flags >> 2) & 0x01), ((flags >> 1) & 0x01), (flags & 0x01));

	if(flags >> 5)
	{
		printf("\t\t\tURG Flag: Packet Contains Urgent Data\n");
	}
	if((flags >> 4) & 0x01)
	{
		printf("\t\t\tACK Flag: Ack Number Is Valid\n");
	}
	if((flags >> 3) & 0x01)
	{
		printf("\t\t\tPSH Flag: Data Should be pushed to Application\n");
	}
	if((flags >> 2) & 0x01)
	{
		printf("\t\t\tRST Flag: Reset Packet\n");
	}
	if((flags >> 1) & 0x01)
	{
		printf("\t\t\tSYN Flag: Synchronize Packet\n");
	}
	if(flags & 0x01)
	{
		printf("\t\t\tFIN Flag: Finish Packet\n");
	}

	printf("\t\tWindow Size = %d\n", window_size);
	printf("\t\tChecksum = 0x%x\n", checksum);
	printf("\t\tUrgent Pointer = 0x%x\n", urgent_ptr);

	int i = 0;
	int options_len = 0;
	if(header_len == 20)
	{
		printf("No Options\n");
	}
	else
	{
		options_len = header_len - 20;
		printf("\t\tOptions: ");
		printf("0x");
		for(i = 0; i < options_len; i++)
		{
			printf("%x", p[i + 54]);
		}
		printf("\n");
	}
	
	//program 3 additions
	//p. 223, 459
	if(dest_port == 53 || src_port == 53)
	{
		num_dns_packets++;
	}
	else if(dest_port == 25 || src_port == 25)
	{
		num_smtp_packets++;
		printf("SMTP Payload: ");
		print_payload_ascii(p + 54, header_len);//fix TODO
		
	}
	else if(dest_port == 110 || src_port == 110)
	{
		num_pop_packets++;
		printf("POP Payload: ");
		print_payload_ascii(p + 54, header_len);
	}
	else if(dest_port == 143 || src_port == 143)
	{
		num_imap_packets++;
		printf("IMAP Payload: ");
		print_payload_ascii(p + 54, header_len);
	}
	else if(dest_port == 80 || src_port == 80) //HTTPS omitted
	{
		num_http_packets;
		printf("HTTP Payload: ");
		print_payload_ascii(p + 54, header_len);

	}

	//printf("\t\t------------END Decoding------------\n");

}


//program 3 additions
print_payload_ascii(const u_char *p, const uint8_t len)
{
	const u_char *ch;
	int i;

	ch = p;
	for(i = 0; i < len; i++)
	{
		if(isprint(*ch)) //check if convertable to ascii
		{
			printf("%c", *ch);
			ch++;
			//printf("%c", p[i]);
		}
	}
}


/*
insert your code in this routine

*/

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int length = h->len;
    u_int caplen = h->caplen;
	
	printf("--------START Decoding Ethernet Header--------\n");
	//1 print dest and source addr
	printf("Dest Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[0], p[1], p[2], p[3], p[4], p[5]);
	printf("Source Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[6], p[7], p[8], p[9], p[10], p[11]);

	//2 print type/eln as  Type = (hex val) or Len = (dec val)
	uint16_t e_type;
	uint16_t limit = 0x600;
	e_type = (p[12] << 8) + p[13];

	if(e_type < limit)
	{
		printf("Length = %0d\n", p[12]);
	}
	else
	{
		printf("Type = 0x%04X\n", e_type);
	}
	
	//3 print ethernet protocol being used. eg. if type is 0x0800, then pring payload = IPv4

	switch(e_type)
	{
		case 0x800:
			printf("Payload = IPv4\n");
			printf("--------END Decoding-------\n");
			print_ip_header(p);
			num_ip_packets++;
			break;
		
		case 0x0806:
			printf("Payload = ARP\n");
			printf("--------END Decoding--------\n");
			print_arp_header(p);
			num_arp_packets++;
			break;	
	}
	
	default_print(p, caplen);
	putchar('\n');
}

