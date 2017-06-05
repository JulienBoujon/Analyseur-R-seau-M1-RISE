#include "DNS_loc.h"

void handle_DNS_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//Fonction de gestion des paquest DNS en verbosité 2
	struct DNS_HEADER *eptr; 
    eptr = (struct DNS_HEADER *) packet;
    printf("Message :");
    switch (eptr->opcode){
    	case 0:
    		printf("Query\n");
    		break;
    	case 1:
    		printf("Inversed Query\n");
    		break;
    	case 2:
    		printf("Status\n");
    		break;
    	case 4:
    		printf("Notify\n");
    		break;
    	case 5:
    		printf("Update\n");
    		break;
    	default:
    		printf("Non assigné\n");
    		break;
    }
}

void handle_DNS_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//Fonction de gestion des paquest DNS en verbosité 3
	struct DNS_HEADER *eptr; 
    eptr = (struct DNS_HEADER *) packet;
    if(eptr->rd==1){
    	printf("Récursivité demandée\n");
    }
    if(eptr->ra==1){
    	printf("Récursivité disponible\n");
    }
    printf("Message :");
    switch (eptr->opcode){
    	case 0:
    		printf("Query\n");
    		break;
    	case 1:
    		printf("Inversed Query\n");
    		break;
    	case 2:
    		printf("Status\n");
    		break;
    	case 4:
    		printf("Notify\n");
    		break;
    	case 5:
    		printf("Update\n");
    		break;
    	default:
    		printf("Non assigné\n");
    		break;
    }
    printf("Type de réponse : ");
    switch (eptr->rcode){
    	case 0:
    		printf("Pas d'erreur\n");
    		break;
    	case 1:
    		printf("Erreur de format de reqête\n");
    		break;
    	case 2:
    		printf("Problème sur le serveur\n");
    		break;
    	case 3:
    		printf("Le nom demandé n'existe pas\n");
    		break;
    	case 5:
    		printf("Refus\n");
    		break;
    	default:
    		printf("Non assigné\n");
    		break;
    }
}