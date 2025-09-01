#define APP_NAME		"devsfinder"
#define APP_DESC		"a helper tool to the NetworkSniffer tool by Amirreza Fatemi Salanghooch"
#define APP_COPYRIGHT		"© 2025 Amirreza Fatemi Salanghooch. All Rights Reserved"
#define APP_DISCLAIMER		"THERE ARE NO RESTRICTIONS ON USING THIS TOOL UNDER THE COPYRIGHT FRAMEWORK. ENJOY IT :)"
#define APP_CONTACT		"You can reach me out through my email and see my projects through my github.\n\nEmail : amirrezafatemi@gmail.com\n\nLink to this project online : https://github.com/amirrezafatemi/NetworkSniffer"

#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void sys() {
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
	printf("\033[1m%s - %s\n", APP_NAME, APP_DESC);
	printf("\033[1m%s\n", APP_COPYRIGHT);
	printf("\033[1m%s\n", APP_DISCLAIMER);
	printf("\033[1m%s\n", APP_CONTACT);

}


int def () {
	
	sys ();

	intro ();

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;

	if (pcap_findalldevs ( &alldevs, errbuf) == PCAP_ERROR){
		printf ("\033[1;31m[-]\033[0m\033[1m ERROR IN pcap_findalldevs : %s\n\033[0m", errbuf);
	} else{		
		printf ("\n\n\033[1m[\033[32mINFO\033[0m\033[1m] -> Network Devices :\n\033[0m");	
		for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
			printf ("\n\t\033[1m[\033[32m+\033[0m\033[1m] Device : %s \033[0m", dev->name);
			if (dev->flags & PCAP_IF_UP) printf ("\033[1;36m[UP]\033[0m");
			if (dev->flags & PCAP_IF_WIRELESS){ 
				printf ("\033[1;34m[WIRELESS]\033[0m");
				if (dev->flags & PCAP_IF_LOOPBACK){
					printf ("\033[1;33m[LOOPBACK]\033[0m");
				} else{	
					if (dev->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED) printf("\033[1;32m[CONNECTED]\033[0m");
					if (dev->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED) printf("\033[1;31m[DISCONNECTED]\033[0m");
				}
			}
			if (!dev->description){
				printf ("\n\t\t\033[1m[\033[31mDESCRIPTION\033[0m\033[1m] : NO DESCRIPTION\033[0m");
			} else{
			      	printf ("\n\t\t\033[1m[\033[31mDESCRIPTION\033[0m\033[1m] : %s\033[0m", dev->description);
			}
		
			for (pcap_addr_t * pcapaddr = (dev->addresses); pcapaddr != NULL; pcapaddr = pcapaddr->next){
				if (pcapaddr->addr->sa_family == AF_INET){
					struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)pcapaddr->addr;
					char ipv4_str[INET_ADDRSTRLEN];
					if (inet_ntop (AF_INET, &ipv4_addr->sin_addr, ipv4_str, sizeof (ipv4_str)) != NULL){
						printf("\n\t\t\033[1m[\033[32mIPv4\033[0m\033[1m] : %s\033[0m", ipv4_str);
					} else{
						perror ("inet_ntop");
					}
			
				} else if(pcapaddr->addr->sa_family == AF_INET6){
					struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)pcapaddr->addr;
					char ipv6_str[INET6_ADDRSTRLEN];	
					if (inet_ntop (AF_INET6, &ipv6_addr->sin6_addr, ipv6_str, sizeof (ipv6_str)) != NULL){
						printf ("\n\t\t\033[1m[\033[32mIPv6\033[0m\033[1m] : %s\033[0m", ipv6_str);

					} else{
						perror ("inet_ntop");			
					}
				}
			}
			printf ("\n\n");
		}
	}

	pcap_freealldevs(alldevs);

	char * defaultdev = pcap_lookupdev( errbuf);
	if (!defaultdev){
		printf ("\033[1;31m[-]\033[0m\033[1m ERROR IN pcap_lookupdev : %s\n\033[0m");
	} else{
		printf ("\n\n\033[1m╔══════════════════════════════════════════════════════════════════════╗\033[0m");
		printf ("\n\n\033[1m  [\033[32mINFO\033[0m\033[1m] -> If you don't know which device to use for capturing,\n  this network interface is the default device which is not a loopback\n  and ready to capture packets\n\n   :%s", defaultdev);
		printf ("\n\n╚══════════════════════════════════════════════════════════════════════╝");
		printf ("\n\nPRESS CTRL+C TO EXIT . . .\n");
	}

	return 0;
}

int main(int argc, char **argv){
	if (argc != 1){
		printf ("\033[1mThat\'s not how it works. just type \033[32m%s\033[0m\n", argv[0]);
	} else{
		def();
		while (true){
			char canc = getchar();
			if (canc == EOF){
				break;
			} else{
				def();
			}
		}
	}
	return 0;
}
