
#ifndef SCANNER_H
#define SCANNER_H

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <map>
#include <unistd.h>
#include <thread>

#include <vector>
#include <string>
#include <algorithm>

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

using std::string;

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

uint16_t checksum (uint16_t *addr, int len);
uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);

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

struct eth_header{
	unsigned char type;
	unsigned char length;
	unsigned char mac[6];

};

struct icmpv6_header{
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	char target[16];
	struct eth_header eth;
};

struct interface{
	char name[IFNAMSIZ];
	unsigned char mac[6];
	unsigned int index;
	unsigned int hostip;
	unsigned int subnet_mask;
	unsigned int network;
	std::vector<string> hostip6;
};
struct mac_ip{
	unsigned char mac[6];
	unsigned char **ipv4;
	unsigned char **ipv6;
};

class NetworkScanner{

public:
	NetworkScanner();
	void scan(char *iface);
	void write(char *filename);

private:
	int socketd;
	interface iface;
	std::map<string, std::vector<string>> mac_ipv4;
	std::map<string, std::vector<string>> mac_ipv6;

	void add(std::map<string, std::vector<string>> *_map, string key, string value);
	unsigned int recv_timeout_s;
	bool socket_opened;
	void loadInterfaceInfo(char *iname);
	void receiveICMPv6();
	std::vector<string> getLocalIpv6Adresses(char *iface);
	void sendIcmpv6(char* src, char* dst);
	int sendNS(char* src, char* dst);
	void sendARPRequest(unsigned int dst);
	void receiveARPRequest();
	void scanIpv4Hosts(int tries);
	void scanIpv6Hosts(int tries);
	void openSocket(int packetType, int socketType, int unknown);
	void closeSocket();
	unsigned int reorderIPv4(unsigned int ip);
	void printIPv4(unsigned int ip);
};


#endif
