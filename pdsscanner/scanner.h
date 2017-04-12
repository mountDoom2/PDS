
#ifndef SCANNER_H
#define SCANNER_H

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#ifdef DEBUG
#define debug(x...) printf("DEBUG: ");printf(x);printf("\n");
#else
#define debug(x...);
#endif

class NetworkScanner{

public:
	char *interface;
	NetworkScanner();
	void scan(char *iface);
	void write(char *filename);
	struct ifreq ifr;

private:
	int socketd;
	unsigned char mac[6];
	unsigned int ipv4;
	int ipv6;
	bool socket_opened;
	void loadInterfaceInfo(char *iname);
	void openSocket(int packetType, int socketType, int unknown);
	void closeSocket();
};

struct arp_header{
    unsigned short hwtype;
    unsigned short pttype;
    unsigned char hw_addr_len;
    unsigned char pt_addr_len;
    unsigned short opcode;
    unsigned char sha[6];
    unsigned char spa[4];
    unsigned char tha[6];
    unsigned char tpa[4];
};


#endif
