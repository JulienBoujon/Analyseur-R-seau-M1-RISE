#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <netinet/ether.h> 

void handle_ARP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_ARP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);