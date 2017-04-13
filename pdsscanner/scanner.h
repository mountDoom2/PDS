
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

int read_arp(int fd);


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
	unsigned int iface_index;
	unsigned int subnet_mask;
	int ipv6;
	bool socket_opened;
	void loadInterfaceInfo(char *iname);
	//void buildARPRequest(struct arp_header *arp);
	void buildARPRequest(struct arp_header *arp, unsigned int dst_ip);
	void openSocket(int packetType, int socketType, int unknown);
	void closeSocket();
	unsigned int reorderIPv4(unsigned int ip);
	void printIPv4(unsigned int ip);
};

struct arp_header{
    unsigned short hwtype;
    unsigned short pttype;
    unsigned char hw_addr_len;
    unsigned char pt_addr_len;
    unsigned short opcode;
    unsigned char source_mac[6];
    unsigned char source_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};


#endif
