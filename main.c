#define APP_NAME		"NetworkSniffer"
#define APP_DESC		"a network sniffer using libpcap"
#define APP_COPYRIGHT		"© 2025 Amirreza Fatemi Salanghooch. All Rights Reserved"
#define APP_DISCLAIMER		"THERE ARE NO RESTRICTIONS ON USING THIS TOOL UNDER THE COPYRIGHT FRAMEWORK. ENJOY IT :)"
#define APP_CONTACT		"You can reach me out through my email and see my projects through my github.\n\nEmail : amirrezafatemi@gmail.com\n\nLink to this project online : https://github.com/amirrezafatemi/NetworkSniffer"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "header.h"
#include "main_functions.h"

#define SIZE_ETHERNET 14

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];

void packet_handler (u_char *user, const struct pcap_pkthdr *header, const u_char *data) {

        printf ("\n\033[1;36m∴∷∵∷∵∴∷∵∷∷∵∴∷∵∷∴∷∵∷∵∴∷∵∷∵∴∷∵∵∷∷∵∷∵∷∵∵∵∷∵∷∵∷∵∷∵∴∷∵∷∷∵∷∵∴∵∷∷∵∴∷∵∷∵∴∷∵∷∵∷∵∴∷∵∷∷∵∷∵∷∵\033[0m\n\n");

	printf ("\n\033[1m[\033[32m+\033[0m\033[1m]"
			" Receieved %d bytes (actual packet size : %d)\n\n", header->caplen, header->len);
	printf ("   \033[1m[\033[31mINFO\033[0m\033[1m] :\n");

	short unsigned int protocol;
	unsigned char ipv4_len;
	short unsigned int ipv4_total_len;
	unsigned char ipv4_protocol;
	unsigned char tcp_len;

	if (pcap_datalink (handle) == DLT_EN10MB) {
		parse_ethernet (data, &protocol);
	}

	if (protocol == IPV4_PROTOCOL) {
		parse_ipv4 (data + sizeof (struct ethernet_header), &ipv4_len, &ipv4_protocol, &ipv4_total_len);
		if (ipv4_protocol == ICMP_PROTOCOL) parse_icmp (data + sizeof (struct ethernet_header) + ipv4_len);
		else if (ipv4_protocol == TCP_PROTOCOL) {
		      parse_tcp (data + sizeof (struct ethernet_header) + ipv4_len, ipv4_len, ipv4_total_len);
		}else if (ipv4_protocol == UDP_PROTOCOL) parse_udp (data + sizeof (struct ethernet_header) + ipv4_len);
	}else if (protocol == ARP_PROTOCOL) {
		parse_arp (data + sizeof (struct ethernet_header));


	printf ("\n\033[1;36m∴∷∵∷∵∴∷∵∷∷∵∴∷∵∷∴∷∵∷∵∴∷∵∷∵∴∷∵∵∷∷∵∷∵∷∵∵∵∷∵∷∵∷∵∷∵∴∷∵∷∷∵∷∵∴∵∷∷∵∴∷∵∷∵∴∷∵∷∵∷∵∴∷∵∷∷∵∷∵∷∵\033[0m\n\n");
	}
}

void sys () {

	#ifdef _WIN32 
		system ("cls");
	#ifdef _WIN64
		system ("cls");
	#endif
	#else
		system ("clear");
	#endif

}

void intro () {

	printf ("\n\n\033[1m╔═══════════════════════════════════════════════════════════════╗\033[0m\n");
	printf ("\033[1m  A Personal Project (github.com/amirrezafatemi/NetworkSniffer)\033[0m\n");
	printf ("\033[1m╚═══════════════════════════════════════════════════════════════╝\033[0m\n\n");
	printf ("\033[1m%s - %s\n", APP_NAME, APP_DESC);
	printf ("\033[1m%s\n", APP_COPYRIGHT);
	printf ("\033[1m%s\n", APP_DISCLAIMER);
	printf ("\033[1m%s\n", APP_CONTACT);

}

void usage () {
	
	printf ("\033[1;31musage\033[0m\033[1m: %s <interface>\n\n"
			"\033[0m\033[1;31mOptions\033[0m\033[1m:\n"
			"    interface    Listen on <interface> for packets.\n\n"
			"If you don\'t know your current interfaces,"
				" try running\033[32m ./devsfinder\033[0m", APP_NAME);

}

int main (int argc, char **argv) {

	if (argc < 2){
		usage ();
		return -1;
	}

//	char filter_str[] = "udp"; // Bayad Betonam Filter Haro Be Entekhab User Bezaram						   
//	struct bpf_program filter;

	pcap_if_t *alldevs;

	handle = pcap_open_live (argv[1], BUFSIZ, 1, 5000, errbuf);

	if (!handle){
		printf ("\033[1m[\033[31m-\033[0m\033[1m] ERROR IN pcap_open_live : %s\033[0m\n", errbuf);
		return -1;
	}
	
	sys ();

	intro ();
	
	printf ("\n\033[1;31mCTRL + C TO EXIT . . .\033[0m");

//	if (pcap_compile(handle, &filter, filter_str, 1, 0) == -1) {
//		fprintf(stderr, "\033[1m[\033[31m-\033[0m\033[1m]Couldn't parse filter %s: %s\033[0m\n",
//		    filter_str, pcap_geterr(handle));
//		exit(EXIT_FAILURE);
//	}


//	if (pcap_setfilter(handle, &filter) == -1) {
//		fprintf(stderr, "\033[1m[\033[31m-\033[0m\033[1m]Couldn't install filter %s: %s\033[0m\n",
//		    filter_str, pcap_geterr(handle));
//		exit(EXIT_FAILURE);
//	}
	pcap_loop (handle, -1, &packet_handler, NULL);

//	pcap_freecode (&filter);
//	pcap_close (handle);

	return 0;
}
