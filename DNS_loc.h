#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "DNS.h"

void handle_DNS_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_DNS_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);