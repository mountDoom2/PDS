
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
#define debug(x...); printf("DEBUG: ");printf(x);printf("\n");
#else
#define debug(x...);
#endif

// IPv4 defines
#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

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

struct interface{
	unsigned char mac[6];
	unsigned int index;
	unsigned int hostip;
	unsigned int subnet_mask;
	unsigned int network;
};

int read_arp(int fd);


class NetworkScanner{

public:
	char *iname;
	NetworkScanner();
	void scan(char *iface);
	void write(char *filename);
	//struct ifreq ifr;

private:
	int socketd;
	interface iface;

	unsigned int recv_timeout_s;
	int ipv6;
	bool socket_opened;
	void loadInterfaceInfo(char *iname);
	void sendARPRequest(unsigned int dst);
	void receiveARPRequest();
	void scanIpv4Hosts();
	void openSocket(int packetType, int socketType, int unknown);
	void closeSocket();
	unsigned int reorderIPv4(unsigned int ip);
	void printIPv4(unsigned int ip);
};


#endif
