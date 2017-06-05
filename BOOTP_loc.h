#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <math.h>
#include <netinet/ether.h>
#include "bootp.h"

typedef struct {
	u_int8_t type;
	u_int8_t length;
	u_int8_t value[32];
} vendor;

void printipvendor(vendor opt);
void handle_BOOTP_V1(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_BOOTP_V2(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_BOOTP_V3(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);