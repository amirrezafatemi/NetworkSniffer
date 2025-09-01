/* Ethernet addresses' length are 6 bytes */

/* ETHERNET HEADER */
#define ETHER_ADDR_LEN 6
#define IPV4_PROTOCOL 0x0800
#define ARP_PROTOCOL 0x0806

/* IPv4 HEADER */
#define ICMP_PROTOCOL 1
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

/* Ethernet header*/
/* parses the first 14 bytes of an Ethernet frame */
struct ethernet_header {
	unsigned char mac_dst[6];	/* destination host address */
	unsigned char mac_src[6];	/* source host address */
	short unsigned int protocol;	/* detects the EtherTypes */
					/* EtherTypes:
					 *		0x0800 (IPv4)
					 *		0x0806 (ARP)
					 *		0x8035 (RARP)
					 *		0x8100 (802.1Q VLAN-tagged frame)
					 *		0x86DD (IPv6)
					 *		0x8847 (MPLS unicast)
					 *		0x8808 (MPLS multicast)
					 *		0x8808 (Ethernet flow control (PAUSE frames))
					 *		0x88CC (LLDP)
					 *		0x22F3 (IETF TRILL Protocol)
					 *		0x6003 (DECnet Phase IV)
					 * */
} __attribute__((packed)) ;

/* IPv4 header */
/* parses the IPv4 header that comes next (usually starting at byte 14) */
struct ipv4_header {
	unsigned char ip_v_hl;					/* Version & IHL */
	unsigned char ip_tos;					/* TOS (type of service) */
	short unsigned int ip_total_len;			/* total length */
	short unsigned int ip_identification;			/* identification */
	short unsigned int ip_frags_fragment_offset;		/* fragment offset field */
	unsigned char ip_ttl;					/* time to live */
	unsigned char ip_proto;					/* protocol field
								 *  specifies the next layer protocol (TCP, UDP, ICMP, etc)
								 *  e.g. IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
								 *  	 IPPROTO_IP
								 * */
	
	short unsigned int ip_checksum;				/* header checksum for error-checking th IP header*/
	unsigned int ip_src, ip_dst;				/* source and destination IP address */
} __attribute__((packed)) ;

/* ARP header */
struct arp_header {
	short unsigned int hardware_type;		/* Hardware Type */
	short unsigned int protocol_type;		/* Protocol Type */
	unsigned char hardware_length;			/* Hardare Length */
	unsigned char protocol_length;			/* Protocol Length */	
	short unsigned int operation;			/* Operation */
	unsigned char mac_src[6];			/* Sender Hardware Address (MAC Source) */
	unsigned int ip_src;				/* Sender Protocol Address (IP Source) */
	unsigned char mac_dst[6];			/* Target Hardware Address */
	unsigned int ip_dst;				/* Target Protocol Address */
} __attribute__ ((packed)) ;

/* ICMP header */
/* This structure that I written down here 
 * is a general header for ICMPv4.
 * More micros can be defined specifically 
 * if we want to show more content about the imcp packets 
 * by controlling the Type and Code. 
 * */
struct icmp_header {
	unsigned char icmp_type;			/* Type */
	unsigned char icmp_code;			/* Code */
	short unsigned int icmp_checksum;		/* Checksum */
							/* I didn't define the Content
							 * because Control messages are identified 
							 * by the value in the type field. 
							 * Also, The code field gives additional context information
							 * for the message.
							 * In future, I will add more structures.
							 * */
} __attribute((packed));

/* UDP header */
struct udp_header {
	short unsigned int udp_port_src;		/* source port */
	short unsigned int udp_port_dst;		/* destination port */
	short unsigned int udp_length;			/* lenght */
	short unsigned int udp_checksum;		/* checksum */

} __attribute__((packed));

/* TCP header */
typedef unsigned int tcp_seq;

struct tcp_header {
	short unsigned int tcp_port_src;					/* source port */
       	short unsigned int tcp_port_dst;					/* destination port */
	tcp_seq tcp_header_seq_num;						/* sequence number */
	tcp_seq tcp_header_ack_num;						/* acknowledgement number */
	unsigned char tcp_header_offsetx2;						/* data offset */
#define TCP_HEADER_OFFSET(tcp)	(((tcp)->tcp_header_offsetx2 & 0xf0) >> 4)
	unsigned char tcp_header_flags;
#define TCP_HEADER_FIN 0x01
#define TCP_HEADER_SYN 0x02
#define TCP_HEADER_PUSH 0x08
#define TCP_HEADER_ACK 0x10
#define TCP_HEADER_URG 0x20
#define TCP_HEADER_ECE 0x40
#define TCP_HEADER_CWR 0x80
#define TCP_HEADER_FLAGS (TCP_HEADER_FIN|TCP_HEADER_SYN|TCP_HEADER_RST|TCP_HEADER_ACK|TCP_HEADER_URG|TCP_HEADER_ECE|TCP_HEADER_CWR)
	short unsigned int tcp_header_window;					/* window */
	short unsigned int tcp_header_checksum;					/* checksum */
	short unsigned int tcp_header_urgent_pointer;				/* urgent pointer */
} __attribute__((packed)) ;
