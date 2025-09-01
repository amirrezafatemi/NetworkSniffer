#ifndef FUNCTIONS_H_INCLUDED
#define FUNCTIONS_H_INCLUDED

void print_readable_data (const u_char *data, int len, int offset);

void print_raw_data (const u_char *tcp_payload, int len);

void parse_ethernet (const u_char *ethernet_start, short unsigned int *protocol);

void parse_ipv4 (const u_char *ipv4_start, unsigned char *ipv4_length, unsigned char *ipv4_proto_ref, short unsigned int *ipv4_total_length);

void parse_arp (const u_char *arp_start);

void parse_tcp (const u_char *tcp_start, int ipv4_len, int ipv4_total_len);

void parse_icmp (const u_char *icmp_start);

void parse_udp (const u_char *udp_start);

#endif
