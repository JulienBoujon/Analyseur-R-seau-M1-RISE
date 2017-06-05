#include "UDP.h"

void handle_UDP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquer UDP en verbosité 1
	struct udphdr *eptr; 
    eptr = (struct udphdr *) packet;
    u_char *app_pckt=(u_char *)packet+8;
    if((ntohs(eptr->uh_sport)==67)||(ntohs(eptr->uh_sport)==68)||(ntohs(eptr->uh_dport)==67)||(ntohs(eptr->uh_dport)==67)){
    	printf("BOOTP\n");
    	handle_BOOTP_V1(args,pkthdr,app_pckt);
    }
    if((ntohs(eptr->uh_sport)==53)||(ntohs(eptr->uh_dport)==53)){
        printf("DNS\n");
    }
}

void handle_UDP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquer UDP en verbosité 2
	struct udphdr *eptr; 
    eptr = (struct udphdr *) packet;
    u_char *app_pckt=(u_char *)packet+8;
    printf("Port source : %d\n",ntohs(eptr->uh_sport));
    printf("Port destination : %d\n",ntohs(eptr->uh_dport));
    if((ntohs(eptr->uh_sport)==67)||(ntohs(eptr->uh_sport)==68)||(ntohs(eptr->uh_dport)==67)||(ntohs(eptr->uh_dport)==67)){
    	printf("\nBOOTP\n");
    	handle_BOOTP_V2(args,pkthdr,app_pckt);
    }
    if((ntohs(eptr->uh_sport)==53)||(ntohs(eptr->uh_dport)==53)){
        printf("\nDNS\n");
        handle_DNS_V2(args,pkthdr,app_pckt);
    }
}

void handle_UDP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquer UDP en verbosité 3
	struct udphdr *eptr; 
    eptr = (struct udphdr *) packet;
    u_char *app_pckt=(u_char *)packet+8;
    printf("Port source : %d\n",ntohs(eptr->uh_sport));
    printf("Port destination : %d\n",ntohs(eptr->uh_dport));
    printf("Taille : %d\n",ntohs(eptr->uh_ulen));
    printf("Checksum : %d\n",ntohs(eptr->uh_sum));
    if((ntohs(eptr->uh_sport)==67)||(ntohs(eptr->uh_sport)==68)||(ntohs(eptr->uh_dport)==67)||(ntohs(eptr->uh_dport)==67)){
        printf("\nBOOTP\n");
        handle_BOOTP_V3(args,pkthdr,app_pckt);
    }
    if((ntohs(eptr->uh_sport)==53)||(ntohs(eptr->uh_dport)==53)){
    	printf("\nDNS\n");
    	handle_DNS_V3(args,pkthdr,app_pckt);
    }
}
