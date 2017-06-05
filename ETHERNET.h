#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include "IP.h"
#include "ARP.h"
#include <netinet/ether.h>

void handle_ethernetV1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_ethernetV2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_ethernetV3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
