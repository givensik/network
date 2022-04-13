#include <pcap.h>

#include <stdbool.h>

#include <stdio.h>

#include "libnet1.h"

void usage() {

    printf("syntax: pcap-test <interface>\n");

    printf("sample: pcap-test wlan0\n");

}



int main(int argc, char* argv[]) {

    if (argc != 2) {

        usage();

        return -1;

    }



    char* interface = argv[1];



    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {

        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);

        return -1;

    }



    while (true) {

        struct pcap_pkthdr* header;

        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

            break;

        }
	int i;
	printf("--------start--------\n");
        printf("%u bytes captured\n\n", header->caplen);
	//1. ethernet_header
	struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
	printf("Source Mac : ");
	for(i=0;i<4;i++){
		printf("%02x",eth->ether_shost[i]);
		if(i!=3){
			printf(":");
		}
	}
	printf("\n");
	printf("Destination Mac : ");
	for(i=0;i<4;i++){
		printf("%02x",eth->ether_dhost[i]);
		if(i!=3){
			printf(":");
		}
	}
	printf("\n\n");
	
	//2.ip header
		
	struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr*)(packet+sizeof(libnet_ethernet_hdr));
	
	printf("IP header src : ");
	for(i=0;i<4;i++){
		printf("%d",((iphdr->ip_src.s_addr)>>8*i)&0xff);
		if(i!=3){
			printf(".");
		}
	}
	printf("\n");
	
	printf("IP header drc : ");
	for(i=0;i<4;i++){
		printf("%d",((iphdr->ip_src.s_addr)>>8*i) & 0xff );
		if(i!=3){
			printf(".");
		}
	}
	printf("\n\n");
	//tcp port
	struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr*)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr));

	printf("source port : %d\n",tcphdr->th_sport);
	printf("destination port : %d\n\n",tcphdr->th_dport);

	
	//payload
	
	const u_char* data = packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr);
	printf("payload : ");
	for(i=0;i<8;i++){
		printf("%0x ",data[i]);
	}
	printf("\n\n");

    }



    pcap_close(pcap);

}
