#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include "ETHERNET.h"

#define BUFSIZE 10000

int verbose=1;//initialisation de la verbosité à 1, valeur d'éxécution par défaut si l'utilisateur ne la précise pas
int numpckt=0;//numéro de paquet

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){ //
    numpckt++;
    printf("\n-----------------------------------------------\n");
    printf("Paquet %d\n",numpckt);
    switch (verbose){
        case 1:
            handle_ethernetV1(args,pkthdr,packet);
            break;
        case 2:
            handle_ethernetV2(args,pkthdr,packet);
            break;
        case 3:
            handle_ethernetV3(args,pkthdr,packet);
            break;
        default:
            printf("Verbosité non reconnue, 1, 2 ou 3 sont correctes.\n");
            exit(1);
    }
}


int main(int argc,char **argv){ 
    char *dev=NULL;//nom de l'interface sélectionnée par l'utilisateur ou sélectionée automatiquement
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr=NULL;
    bpf_u_int32 maskp;//masque de sous-réseau
    bpf_u_int32 netp;//address IP
    u_char* args=NULL;
    int c;
    int promisc=0;//par défaut, mode promisious désactivé
    int t=0;//par défaut, capture infinie de trame (jusqu'a appuie sur ctrl+c)
    int o=0;//par défaut, capture online
    int i=0;//test de spécification d'inteface
    char *file;//nom du fichier pour le mode offline
    verbose=1;//verbosité 1 si non précisé
    while ((c = getopt(argc , argv, "pt:v:o:i:")) != -1){
        switch (c){
            case 'p':
                promisc=1;
                printf("Mode promiscious activé \n");
                break;
            case 't':
                t=atoi(optarg);
                printf("%d paquest seront capturés\n",t);
                break;
            case 'v':
                verbose=atoi(optarg);
                printf("Verbosité %d sélectionnée\n",verbose);
                break;
            case 'o':
                o=1;
                printf("Utilisation d'un fichier de captures\n");
                file=optarg;
                break; 
            case 'i':
                i=1;
                dev=optarg;
                printf("Capture imposée sur l'inteface %s\n",dev);
                break;
            case '?':
                if (optopt == 't'){
                    fprintf (stderr, "L'option -%c nécessite un argument. \nVeuillez entrer le nombre de paquets désirés.\n", optopt);
                }
                else if (optopt=='v'){
                    fprintf (stderr, "L'option -%c nécessite un argument. \nVeuillez entrer la verbosité désirée (1, 2 ou 3).\n", optopt);
                }
                else if (optopt=='o'){
                    fprintf (stderr, "L'option -%c nécessite un argument. \nVeuillez entrer le nom du fichier de capture.\n", optopt);
                }
                else if (optopt=='i'){
                    fprintf (stderr, "L'option -%c nécessite un argument. \nVeuillez entrer le nom de l'interface sur laquelle capturer.\n", optopt);
                }
                else if (isprint (optopt)){
                    fprintf (stderr, "Option inconnue`-%c'.\n Options supportées: -p -v -t\n", optopt);
                }
                else{
                    fprintf (stderr,"Caractère d'option inconnu. `\\x%x'.\n",optopt);
                }
                return 1;
            default:
                abort ();
        }
    }
    if(o==0){//si on n'est pas en mode offline
        if(i==0){//si l'utilisateur ne sélectionne pas d'interface
            dev = pcap_lookupdev(errbuf);//sélection automatique de l'interface
            if(dev == NULL){ 
                printf("%s\n",errbuf); 
                exit(1);
            }
            printf("Interface %s sélectionnée automatiquement\n",dev);
        }
        pcap_lookupnet(dev,&netp,&maskp,errbuf);// détermine le device et le masque de sous-réseau
        descr = pcap_open_live(dev,BUFSIZ,promisc,0,errbuf);//démarre l'éoute avec l'option de promisuité
        if(descr == NULL){ 
            printf("pcap_open_live(): %s\n",errbuf); exit(1); 
        }
    }
    else{
        descr = pcap_open_offline(file, errbuf);//ouverture d'un fichier de capture pour l'utilisation hors-ligne
        if (descr == NULL) {
            printf("%s\n",errbuf);
            exit(1);
        }
    }
    if(pcap_loop(descr,t,my_callback,args)==-1){//répète l'opération avec le nombre de paquets désirés.
        perror("pcap_loop");
        exit(1);
    }
    fprintf(stdout,"\nFin de la capture.\n");
    return 0;
}