#include "BOOTP_loc.h"

void printipvendor(vendor opt){ //fonction d'affichage d'addresse IP dans le vendor specific
	int i;
	for(i=0;i<opt.length;i++){
		if(i!=opt.length-1){
			printf("%d.",opt.value[i]);
		}
		else{
			printf("%d\n",opt.value[i]);
		}
    }
}

void handle_BOOTP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquest BOOTP en verbosité 1
	struct bootp *eptr; 
    eptr = (struct bootp *) packet;
    int test=1,i;
     for(i=0;i<4;i++){//détetion du magic cookie DHCP
    	if((i==0 && eptr->bp_vend[i]!=0x63) || (i==1 && eptr->bp_vend[i]!=0x82) || (i==2 && eptr->bp_vend[i]!=0x53) ||(i==3 && eptr->bp_vend[i]!=0x63)){
    		test=0;
    	}
    }
    if(test==1){
    	printf("DHCP\n");

    }
}

void handle_BOOTP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquest BOOTP en verbosité 2
	struct bootp *eptr; 
    eptr = (struct bootp *) packet;
    int test=1,i;
    if(eptr->bp_op==BOOTREQUEST){
    	printf("Reqête\n");
    }
    else{
    	printf("Réponse\n");
    }
     for(i=0;i<4;i++){//détetion du magic cookie DHCP
    	if((i==0 && eptr->bp_vend[i]!=0x63) || (i==1 && eptr->bp_vend[i]!=0x82) || (i==2 && eptr->bp_vend[i]!=0x53) ||(i==3 && eptr->bp_vend[i]!=0x63)){
    		test=0;
    	}
    }
    if(test==1){
    	printf("\nDHCP\n");

    }
}

void handle_BOOTP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de paquest BOOTP en verbosité 3
	struct bootp *eptr; 
    eptr = (struct bootp *) packet;
    /*intitalisation de la variable de test de présence du cookie, de la variable de boucle et de l'offset (pointeur de la 
    position de l'octet étudié dans le vendor specific, initialisé à 4 pour correpondre à la suide du magic cookie)*/
    int test=1,i,offset=4;
    vendor opt;
    printf("Opcode : %d\n",eptr->bp_op);
    if(eptr->bp_htype==1){
    	printf("Hardware type : Ethernet\n");
    }
    printf("Longueur de l'addresse : %d octets\n",eptr->bp_hlen);
    printf("Gateway Hops : %d\n",eptr->bp_hops);
    printf("@IP Client : %s\n",inet_ntoa(eptr->bp_ciaddr));
    printf("Your IP Address : %s\n",inet_ntoa(eptr->bp_yiaddr));
    printf("@IP du server : %s\n",inet_ntoa(eptr->bp_siaddr));
    printf("@IP Gateway : %s\n",inet_ntoa(eptr->bp_giaddr));
    printf("@mac client : %s\n",ether_ntoa((const struct ether_addr *)&eptr->bp_chaddr));
    printf("Server name : %s\n",eptr->bp_sname);
    for(i=0;i<4;i++){//détetion du magic cookie DHCP
    	if((i==0 && eptr->bp_vend[i]!=0x63) || (i==1 && eptr->bp_vend[i]!=0x82) || (i==2 && eptr->bp_vend[i]!=0x53) ||(i==3 && eptr->bp_vend[i]!=0x63)){
    		test=0;
    	}
    }
    if(test==1){
    	printf("\nDHCP\n");
    	while(opt.type!=0xff){
    		opt.type=eptr->bp_vend[offset];//on récupère le type de TLV
       		offset++;//on décale l'offset
    		opt.length=eptr->bp_vend[offset];//récupération de la taille du TLV
    		//printf("length : %d\n",opt.length);
    		offset++;//on décale l'offset
    		for(i=0;i<opt.length;i++){//récupétation et affichage du contenu de TLV
    			opt.value[i]=eptr->bp_vend[offset];
    			//printf("value [%d] : %d\n",i,opt.value[i]);
    			offset++;
    		}
    		switch (opt.type){
    			case 1:
    				printf("Masque de sous réseau : ");
    				printipvendor(opt);
    				break;
    			case 2:
    				printf("Time offset : %ds\n",((opt.value[0]<<24) | (opt.value[1]<<16)| (opt.value[2]<<8) | opt.value[3]));
    				break;
    			case 3:
    				printf("Router : ");
    				printipvendor(opt);
    				break;
    			case 6:
    				printf("DNS : ");
    				printipvendor(opt);
    				break;
    			case 12:
    				printf("Host name : %s\n",opt.value);
    				break;
    			case 15:
    				printf("Nom de domaine : %s\n",opt.value);
    				break;
    			case 28:
    				printf("Broadcast address");
    				printipvendor(opt);
    				break;
    			case 50:
    				printf("@IP demandée : ");
    				printipvendor(opt);
    				break;
    			case 51:
    				printf("Lease time : %ds\n",((opt.value[0]<<24) | (opt.value[1]<<16)| (opt.value[2]<<8) | opt.value[3]));
    				break;
    			case 53:
    				printf("Type de message DHCP : ");
    				switch(opt.value[0]){
    					case 1:
    						printf("discover\n");
    						break;
    					case 2:
    						printf("offer\n");
    						break;
    					case 3:
    						printf("request\n");
    						break;
    					case 5:
    						printf("ack\n");
    						break;
    					case 7:
    						printf("release\n");
    						break;
    					default:
    						printf("inconnu\n");
    				}
    				break;
    			case 54:
    				printf("@IP serveur : ");
    				printipvendor(opt);
    				break;
    			case 55:
    				printf("Liste des paramètres de la requête : ");
    				for(i=0;i<opt.length;i++){
    					if(i!=opt.length-1){
    						printf("%d ",opt.value[i]);
    					}
    					else{
    						printf("%d\n",opt.value[i]);
    					}
    				}
    				break;
    			case 61:
    				printf("Indantifiant client : ");
	    			if((int)opt.value[0]==1){//affichage de l'adresse mac du client 
	    				for(i=1;i<opt.length;i++){// décalage de 1 de l'affichage dû à la présence du type d'addresse(1 pour ethernet)
							if(i!=opt.length-1){
								printf("%x:",opt.value[i]);
							}
							else{
								printf("%x\n",opt.value[i]);
							}
					    }
					}
					else if((int)opt.value[0]==0){//affichage de l'identifiant du client si différent d'une addres mac
						for(i=1;i<opt.length;i++){// décalage de 1 de l'affichage dû à la présence du type d'addresse(1 pour ethernet)
							if(i!=opt.length-1){
								printf("%c",opt.value[i]);
							}
							else{
								printf("%c\n",opt.value[i]);
							}
					    }
					}
    				break;
    			case 255://Fin du message DHCP, on ne fait rien
    				break;
    			default:
    				printf("Type non reconnu, longeur : %d\n",opt.length);
    				break;
    		}
    	}
    }
}