#include "IP.h"

void handle_IP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	struct ip *eptr; 
    eptr = (struct ip *) packet;
    u_char *tr_pckt=(u_char *)packet+((int)eptr->ip_hl*4);//segment de la couche transport (décalage de 4 fois le hlen indiqué dans l'en-tête)
    if(eptr->ip_p==0x11){
    	printf("Segment UDP\n");
    	handle_UDP_V1(args,pkthdr,tr_pckt);
    }
    else if (eptr->ip_p==0x06){
    	printf("Segment TCP\n");
    	handle_TCP_V1(args,pkthdr,tr_pckt);
    }
    else{
        printf("Partie transport non reconnue\n");
    }
}

void handle_IP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	struct ip *eptr; 
    eptr = (struct ip *) packet;
    u_char *tr_pckt=(u_char *)packet+((int)eptr->ip_hl*4);//segment de la couche transport (décalage de 4 fois le hlen indiqué dans l'en-tête)
    printf("@IP source : %s\n",inet_ntoa(eptr->ip_src));
    printf("@IP destination : %s\n",inet_ntoa(eptr->ip_dst));
    if(eptr->ip_p==0x11){
    	printf("\nSegment UDP\n");
    	handle_UDP_V2(args,pkthdr,tr_pckt);
    }
    else if (eptr->ip_p==0x06){
    	printf("\nSegment TCP\n");
    	handle_TCP_V2(args,pkthdr,tr_pckt);
    }
    else{
        printf("Partie transport non reconnue\n");
    }
}

void handle_IP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	struct ip *eptr; 
    eptr = (struct ip *) packet;
    u_char *tr_pckt=(u_char *)packet+((int)eptr->ip_hl*4);//segment de la couche transport (décalage de 4 fois le hlen indiqué dans l'en-tête)
    printf("Taille en-tête : %d\n",eptr->ip_hl);
    printf("Version : %d\n",eptr->ip_v );
    printf("@IP source : %s\n",inet_ntoa(eptr->ip_src));
    printf("@IP destination : %s\n",inet_ntoa(eptr->ip_dst));
    printf("TTL : %d\n",eptr->ip_ttl);
    if(eptr->ip_p==0x11){
    	printf("\nSegment UDP\n");
    	handle_UDP_V3(args,pkthdr,tr_pckt);
    }
    else if (eptr->ip_p==0x06){
    	printf("\nSegment TCP\n");
    	handle_TCP_V3(args,pkthdr,tr_pckt);
    }
    else{
        printf("Partie transport non reconnue\n");
    }
}