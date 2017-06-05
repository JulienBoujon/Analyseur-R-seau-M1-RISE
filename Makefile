main: main.c ETHERNET.o IP.o UDP.o TCP.o BOOTP.o ARP.o DNS.o
	gcc -Wall main.c ETHERNET.o IP.o TCP.o UDP.o BOOTP.o ARP.o DNS.o -o analyse -lpcap

ETHERNET.o: ETHERNET.c ETHERNET.h IP.o ARP.o
	gcc -c ETHERNET.c -Wall

IP.o: IP.h IP.c UDP.o TCP.o
	gcc -c IP.c -Wall

TCP.o: TCP.c TCP.h
	gcc -c TCP.c -Wall

UDP.o: UDP.c UDP.h BOOTP.o DNS.o
	gcc -c UDP.c -Wall

BOOTP.o: BOOTP_loc.h BOOTP.c
	gcc -c BOOTP.c -Wall

ARP.o: ARP.c ARP.h
	gcc -c ARP.c -Wall

DNS.o: DNS.c DNS.h
	gcc -c DNS.c -Wall

clean:
	rm -rf analyse
	rm -rf *.o