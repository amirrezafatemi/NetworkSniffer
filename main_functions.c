#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "header.h"
#include "main_functions.h"

#define MAX_FLAG_STR_LEN 51

void print_readable_data (const u_char *data, int len, int offset){

	int i;
	int gap;
	const u_char *ch;

	printf("%05d   ", offset);
	ch = data;
	for (i = 0; i < len; i++) {
		printf ("%02x ", *ch);
		ch++;
		if (i == 7)
			printf (" ");
	}

	if (len < 8)
		printf (" ");

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf ("   ");
		}
	}

	printf("   ");
	
	ch = data;
	for (i = 0; i < len; i++) {
		if (isprint (*ch))
			printf ("%c", *ch);
		else
			printf (".");
		ch++;
	}

	printf("\n");

}

void print_raw_data (const u_char *tcp_payload, int len) {

	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;
	const u_char *ch = tcp_payload;

	if (len <= 0)
		return;

	if (len <= line_width) {
		print_readable_data (ch, len, offset);
		return;
	}

	for ( ;; ) {
		line_len = line_width % len_rem;
		print_readable_data (ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_readable_data (ch, len_rem, offset);
			break;
		}
	}

}

void parse_ethernet (const u_char *ethernet_start, short unsigned int *protocol) {

	struct ethernet_header *ethernet = (struct ethernet_header*)(ethernet_start);
	
	printf ("\n\t\033[1m    /*------------------\033[32m ETHERNET HEADER\033[0m\033[1m ------------------*/\033[0m");
	
	printf ("\033[1m\n\t    |\t"
			"[\033[31m+\033[0m\033[1m]   "
			"   SOURCE MAC   : "
			"%02X\033[0m", ethernet->mac_src[0]);
	for (int i = 1; i < 6; i++) printf ("\033[1m:%02X\033[0m", ethernet->mac_src[i]);
	printf ("\033[1m           |\n   \t    "
			"|                                                       |\n\033[0m");

	printf ("\033[1m\t    |\t"
			"[\033[31m+\033[0m\033[1m]"
			"   DESTINATION MAC : "
			"%02X\033[0m", ethernet->mac_dst[0]);
	for (int i = 1; i < 6; i++) printf ("\033[1m:%02X\033[0m", ethernet->mac_dst[i]);
	printf ("\033[1m           |\n\t    "
			"/*-----------------------------------------------------*/\033[0m\n");

	*protocol = ntohs (ethernet->protocol); 
	/* 	*var = ethernet->protocol is big endian
	 * 
	 * YOU CAN ALSO PLAY IT WITH BITWISE OPERATORS :)
	 * 
	 * *var = ethernet->protocol
	 * 	*var = (*var >> 8) || (*var << 8)
	 * */

}

void parse_ipv4 (const u_char *ipv4_start, unsigned char *ipv4_length, unsigned char *ipv4_proto_ref, short unsigned int *ipv4_total_length) {

	struct ipv4_header *ipv4 = (struct ipv4_header*)(ipv4_start);

	unsigned char ip_source[INET_ADDRSTRLEN];
	unsigned char ip_destination[INET_ADDRSTRLEN];
	
	inet_ntop (AF_INET, (const void *)&ipv4->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop (AF_INET, (const void *)&ipv4->ip_dst, ip_destination, INET_ADDRSTRLEN);

	printf ("\n\t\t\033[1m/*----------------\033[32m IPv4 HEADER\033[0m\033[1m ----------------*/\033[0m");

	printf ("\033[1m\n\t\t|\t"
		"[\033[31m+\033[0m\033[1m] From : "
		"%15s\033[0m\t\t", ip_source);
	printf ("\033[1m|\n\t\t"
		"|                                               |\033[0m");

	printf ("\033[1m\n\t\t|\t"
		"[\033[31m+\033[0m\033[1m]  To  : "
		"%15s\t\t\033[0m", ip_destination);
		
	printf ("\033[1m|\n\t\t"
		"/*---------------------------------------------*/\033[0m\n");
	*ipv4_length = ipv4->ip_v_hl & 0b00001111;
	*ipv4_length *= 4;
	*ipv4_proto_ref = ipv4->ip_proto;
	*ipv4_total_length = ntohs (ipv4->ip_total_len);

}

void parse_arp (const u_char *arp_start) {

	struct arp_header *arp = (struct arp_header*)(arp_start);

	unsigned char ip_source[INET_ADDRSTRLEN];
	unsigned char ip_destination[INET_ADDRSTRLEN];
	
	inet_ntop (AF_INET, (const void *)&arp->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop (AF_INET, (const void *)&arp->ip_dst, ip_destination, INET_ADDRSTRLEN);

	printf ("\n\t\033[1m    /*---------------------\033[32m ARP HEADER\033[0m\033[1m ---------------------*/\033[0m");

	if (ntohs (arp->operation) == 1) printf ("\n\t    |\t\033[1m[\033[31m+\033[0m\033[1m]"
						"\tSender is performing for \033[32mREQUEST\033[0m"	
							);
	else printf ("\n\t    |\t\033[1m[\033[31m+\033[0m\033[1m]"
						"\tSender is performing for \033[32mREQUEST\033[0m"	
							);

	printf ("\033[1m             |\n   \t    "
			"|                                                        |\033[0m");			
	
	printf ("\033[1m\n\t    |\t"
			"[\033[31m+\033[0m\033[1m]   "
			"  SOURCE IP    : "
			"%15s\t\t     |\033[0m", ip_source);
	printf ("\033[1m\n\t    |\t"
			"[\033[31m+\033[0m\033[1m]   "
			"  SOURCE MAC   : "
			"%02X\033[0m", arp->mac_src[0]);
	for (int i = 1; i < 6; i++) printf ("\033[1m:%02X\033[0m", arp->mac_src[i]);
	
	printf ("\033[1m             |\n   \t    "
			"|                                                        |\033[0m");
	
	printf ("\033[1m\n\t    |\t"
			"[\033[31m+\033[0m\033[1m]  "
			"   DESTINATION IP  : "
			"%15s\t     |\033[0m", ip_destination);

	printf ("\033[1m\n\t    |\t"
			"[\033[31m+\033[0m\033[1m]  "
			"   DESTINATION MAC : "
			"%02X\033[0m", arp->mac_dst[0]);
	for (int i = 1; i < 6; i++) printf ("\033[1m:%02X\033[0m", arp->mac_dst[i]);
	
	printf ("\033[1m          |\n\t    "
			"/*------------------------------------------------------*/\033[0m\n");

}

void parse_tcp (const u_char *tcp_start, int ipv4_len, int ipv4_total_len) {

	struct tcp_header *tcp = (struct tcp_header*)(tcp_start);
	int size_tcp = TCP_HEADER_OFFSET(tcp)*4;
	if (size_tcp < 20) {
		printf ("\n\t\t\033[1m      "
			"[\033[31m-\033[0m\033[1m] "
			"Invalid TCP header length: %u bytes"
			"\033[0m\n", size_tcp);
	} else{

		printf ("\n\t\033[1m /*------------------------\033[32m TCP HEADER\033[0m\033[1m -------------------------*/\033[0m");

		printf ("\033[1m\n\t |\t"
				"[\033[31m+\033[0m\033[1m] Source Port : "
				"%5d\033[0m", ntohs (tcp->tcp_port_src));
		printf ("\033[1m                                  |\n\t"
				" |                                                               |\033[0m");
		
		char flags_str[MAX_FLAG_STR_LEN] = {0};

                int first = 1;
                int offset = 0;
        
                if (tcp->tcp_header_flags & TCP_HEADER_FIN) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sFIN", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_SYN) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sSYN", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_PUSH) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sPSH", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_ACK) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sACK", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_URG) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sURG", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_ECE) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sECE", first ? "" : " | ");
                        first = 0;
                }
                if (tcp->tcp_header_flags & TCP_HEADER_CWR) {
                        offset += snprintf(flags_str + offset, MAX_FLAG_STR_LEN - offset, "%sCWR", first ? "" : " | ");
                        first = 0;
                }

 
                if (first) snprintf(flags_str, MAX_FLAG_STR_LEN, "None");

                int field_width = 41;
                printf("\033[1m\n\t |\t[\033[31m+\033[0m\033[1m]"
                              " TCP Flags : %-*s|", field_width, flags_str);
                        
                printf ("\033[1m\n\t"
				" |                                                               |\n\033[0m");

		printf ("\033[1m\t |\t"
				"[\033[31m+\033[0m\033[1m] Destination Port : "
				"%5d\033[0m", ntohs (tcp->tcp_port_dst));
		printf ("\033[1m\t\t\t         |\n \t"
				" /*-------------------------------------------------------------*/\033[0m\n");
	}

	const u_char *start_tcp_data = tcp_start + size_tcp;
	int size_tcp_data = ipv4_total_len - (ipv4_len + size_tcp);
	
	if (size_tcp_data > 0) {
		printf ("\n\033[1m   [\033[31mINFO\033[0m\033[1m] -> DECODED TCP HEADER DATA (%d bytes):\n\n", size_tcp_data);
		printf ("OFFSET  HEX                                                 ASCII\n");
		print_raw_data (start_tcp_data, size_tcp_data);
	}

} 

void parse_icmp (const u_char *icmp_start) {

	struct icmp_header *icmp = (struct icmp_header*)(icmp_start);

	printf ("\n\t\t\033[1m/*-----------------\033[32m ICMP HEADER\033[0m\033[1m ----------------*/\033[0m");

		printf ("\033[1m\n\t        |\t"
				"[\033[31m+\033[0m\033[1m] Type : "
				"%d"
				"\tCode : %d\033[0m", icmp->icmp_type, icmp->icmp_code);
		printf ("\033[1m\t\t |\n\t        "
				"|                                                |\n\033[0m");

		printf ("\033[1m\t        |\t"
				"[\033[31m+\033[0m\033[1m] Checksum : "
				"%d\033[0m", icmp->icmp_checksum);
		printf ("\033[1m\t                 |\n\t\t"
				"/*----------------------------------------------*/\033[0m\n");

}

void parse_udp (const u_char *udp_start) {

	struct udp_header *udp = (struct udp_header*)(udp_start);
	const u_char *data_info = udp_start + sizeof (struct udp_header);
	int data_length = ntohs (udp->udp_length) - sizeof (struct udp_header);

	printf ("\n\t\033[1m     /*------------------\033[32m UDP HEADER\033[0m\033[1m ---------------------*/\033[0m");

	printf ("\033[1m\n\t     |\t"
		"[\033[31m+\033[0m\033[1m] SOURCE PORT      : "
		"%5d        		   |\n\t     |\t\t\t\t\t\t\t\t   |\n\t     |\t"
		"[\033[31m+\033[0m\033[1m] DESTINATION PORT : %5d\t\t           |\033[0m",ntohs (udp->udp_port_src), ntohs (udp->udp_port_dst));
	
	printf ("\033[1m\n\t  "
		"   /*---------------------------------------------------*/\033[0m\n");

	printf ("\n\n\033[1m   [\033[31mINFO\033[0m\033[1m] -> DECODED UDP HEADER DATA (%d bytes):\n\n", ntohs (udp->udp_length));
	
	for (int i = 0; i < ntohs (udp->udp_length); i++) printf ("%c", data_info[i]);

}

