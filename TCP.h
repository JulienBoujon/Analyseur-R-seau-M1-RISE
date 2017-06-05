#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pcap.h>

void handle_TCP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_TCP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_TCP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
