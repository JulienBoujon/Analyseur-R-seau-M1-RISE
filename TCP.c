#include "TCP.h"

void handle_TCP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de segment TCP en verbosité 1
	struct tcphdr *eptr; 
    eptr = (struct tcphdr *) packet;
    if((ntohs(eptr->th_dport)==80 || ntohs(eptr->th_sport)==80) && (eptr->th_flags & TH_PUSH)){
    	printf("HTTP\n");
    }
    if((ntohs(eptr->th_dport)==21 || ntohs(eptr->th_sport)==21 || ntohs(eptr->th_sport)==20 || ntohs(eptr->th_dport)==20) && (eptr->th_flags & TH_PUSH)){
        printf("FTP\n");
    }
    if((ntohs(eptr->th_dport)==25 || ntohs(eptr->th_sport)==25) && (eptr->th_flags & TH_PUSH)){
        printf("SMTP\n");
    }
}

void handle_TCP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de segment TCP en verbosité 2
	struct tcphdr *eptr; 
    eptr = (struct tcphdr *) packet;
    if(eptr->th_flags & TH_FIN){
        printf("FIN ");
    }
    if(eptr->th_flags & TH_RST){
        printf("RST ");
    }
    if(eptr->th_flags & TH_URG){
        printf("URG ");
    }   
    if(eptr->th_flags & TH_PUSH){
        printf("PUSH ");
    }
    if(eptr->th_flags & TH_SYN){
        printf("SYN ");
    }
    if(eptr->th_flags & TH_ACK){
        printf("ACK\n");
    }
    if((ntohs(eptr->th_dport)==80 || ntohs(eptr->th_sport)==80) && (eptr->th_flags & TH_PUSH)){
    	printf("\nHTTP\n");
    }
    if((ntohs(eptr->th_dport)==21 || ntohs(eptr->th_sport)==21 || ntohs(eptr->th_sport)==20 || ntohs(eptr->th_dport)==20) && (eptr->th_flags & TH_PUSH)){
        printf("\nFTP\n");
    }
    if((ntohs(eptr->th_dport)==25 || ntohs(eptr->th_sport)==25) && (eptr->th_flags & TH_PUSH)){
        printf("\nSMTP\n");
    }
}

void handle_TCP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){//fonction de gestion de segment TCP en verbosité 3
	struct tcphdr *eptr; 
    eptr = (struct tcphdr *) packet;
    u_char *app_pckt=NULL;
    app_pckt=memset(&app_pckt,0,sizeof(app_pckt));
    app_pckt=(u_char *)packet+((int)eptr->th_off)*4;
    printf("Port source :%d\n",ntohs(eptr->th_sport));
    printf("Port destination :%d\n",ntohs(eptr->th_dport));
    printf("Data Offset: %d\n",eptr->th_off );
   	printf("Flags : %x\n",eptr->th_flags);
   	if(eptr->th_flags & TH_FIN){
        printf("FIN ");
    }
    if(eptr->th_flags & TH_RST){
        printf("RST ");
    }
    if(eptr->th_flags & TH_URG){
        printf("URG ");
    }   
    if(eptr->th_flags & TH_PUSH){
    	printf("PUSH ");
    }
    if(eptr->th_flags & TH_SYN){
    	printf("SYN ");
    }
    if(eptr->th_flags & TH_ACK){
        printf("ACK ");
    }
    printf("\n");
    if((ntohs(eptr->th_dport)==80 || ntohs(eptr->th_sport)==80) && (eptr->th_flags & TH_PUSH)){
    	printf("\nHTTP\n");
    	printf("%s\n",app_pckt);
    }
    if((ntohs(eptr->th_dport)==21 || ntohs(eptr->th_sport)==21 || ntohs(eptr->th_sport)==20 || ntohs(eptr->th_dport)==20) && (eptr->th_flags & TH_PUSH)){
        printf("\nFTP\n");
        printf("%s\n",app_pckt);
    }
    if((ntohs(eptr->th_dport)==25 || ntohs(eptr->th_sport)==25) && (eptr->th_flags & TH_PUSH)){
        printf("\nSMTP\n");
        printf("%s\n",app_pckt);
    }
    memset((void *)app_pckt,'\0',strlen((const char *)app_pckt));//réinitialisation du buffer de packet applicatif
}
