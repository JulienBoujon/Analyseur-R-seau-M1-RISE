#include "ETHERNET.h"

void handle_ethernetV1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//Fonction de gestion des trames ethernet en verbosité 1
    struct ether_header *eptr; 
    eptr = (struct ether_header *) packet;
    u_char *net_pckt=(u_char *)packet+14;// paquet de la couche réseau (décalage de 14 octets correspondant à la taille de l'en-tête)
    printf("Trame ethernet\n");
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP){
        printf("Paquet IP\n");
        handle_IP_V1(args,pkthdr,net_pckt);
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP){
        printf("Paquet ARP\n");
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP){
        printf("Paquet RARP\n");
    }
    else if(ntohs(eptr->ether_type)==ETHERTYPE_IPV6){
        printf("Paquet IPV6\n");
    }
    else {
        printf("(?)\n");
    }
}

void handle_ethernetV2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//Fonction de gestion des trames ethernet en verbosité 2
    struct ether_header *eptr;
    eptr = (struct ether_header *) packet;
    u_char *net_pckt=(u_char *)packet+14;// paquet de la couche réseau (décalage de 14 octets correspondant à la taille de l'en-tête)
    printf("Trame ethernet\n");
    printf("@Mac source: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    printf("@Mac destination: %s \n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP){
        printf("\nPaquet IP\n");
        handle_IP_V2(args,pkthdr,net_pckt);
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP){
        printf("\nPaquet ARP\n");
        handle_ARP_V2(args,pkthdr,net_pckt);
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP){
        printf("\nPaquet RARP :\n");
    }
    else if(ntohs(eptr->ether_type)==ETHERTYPE_IPV6){
        printf("Paquet IPV6\n");
    }
    else {
        printf("(?)\n");
    }
}

void handle_ethernetV3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//Fonction de gestion des trames ethernet en verbosité 3
    struct ether_header *eptr;
    eptr = (struct ether_header *) packet;
    u_char *net_pckt=(u_char *)packet+14;// paquet de la couche réseau (décalage de 14 octets correspondant à la taille de l'en-tête)
    printf("Trame ethernet\n");
    printf("@Mac source: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    printf("@Mac destination: %s \n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP){
        printf("\nPaquet IP\n");
        handle_IP_V3(args,pkthdr,net_pckt);
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP){
        printf("\nPaquet ARP\n");
        handle_ARP_V3(args,pkthdr,net_pckt);
    }
    else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP){
        printf("\nPaquet RARP\n");
    }
    else if(ntohs(eptr->ether_type)==ETHERTYPE_IPV6){
        printf("Paquet IPV6\n");
    }
    else {
        printf("(?)\n");
    }
}