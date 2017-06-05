#include "ARP.h"

void handle_ARP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){ //fonction de gestion de paquet ARP avec la verbosité 2
	struct ether_arp *eptr;
    eptr = (struct ether_arp *) packet;
    switch (ntohs(eptr->arp_op)){
    	case ARPOP_REQUEST:
    		printf("Reqête\n");
    		break;
    	case ARPOP_REPLY:
    		printf("Réponse\n");
    		break;
    	default:
    		printf("Requête ou Réponse RARP ou INARP\n");
    		break;
    }
}

void handle_ARP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquet ARP avec la verbosité 3
	struct ether_arp *eptr;
    eptr = (struct ether_arp *) packet;
    switch (ntohs(eptr->arp_op)){
    	case ARPOP_REQUEST:
    		printf("Reqête\n");
    		break;
    	case ARPOP_REPLY:
    		printf("Réponse\n");
    		break;
    	default:
    		printf("Requête ou Réponse RARP ou INARP\n");
    		break;
    }
    if(ntohs(eptr->arp_hrd)==ARPHRD_ETHER){
    	printf("@mac source : %s\n",ether_ntoa((const struct ether_addr *)&eptr->arp_sha));
    	printf("@IP source : %hhu.%hhu.%hhu.%hhu\n",eptr->arp_spa[0],eptr->arp_spa[1],eptr->arp_spa[2],eptr->arp_spa[3]);
    	printf("@mac source : %s\n",ether_ntoa((const struct ether_addr *)&eptr->arp_tha));
    	printf("@IP source : %hhu.%hhu.%hhu.%hhu\n",eptr->arp_tpa[0],eptr->arp_tpa[1],eptr->arp_tpa[2],eptr->arp_tpa[3]);
    }
}