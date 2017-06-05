#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "BOOTP_loc.h"
#include "DNS_loc.h"

void handle_UDP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_UDP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_UDP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);