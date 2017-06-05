#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "UDP.h"
#include "TCP.h"

void handle_IP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);