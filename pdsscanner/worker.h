//============================================================================
// Name        : worker.h
// Author      : Milan Skala, xskala09
// Version     : 1.0
// Description : Header for Worker object
//============================================================================
#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
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
#include <signal.h>
#include <algorithm> // map methods

#include <libxml/tree.h>
#include <libxml/parser.h>

using namespace std;
using std::string;

#ifdef DEBUG
#define debug(x...); printf("DEBUG: ");printf(x);printf("\n");
#else
#define debug(x...);
#endif

// IPv4 defines
#define MAC_LENGTH 6
#define L2_MULTICAST 0x33330001
#define IPV6_ADDR_LEN 16

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

uint16_t checksum (uint16_t *addr, int len);
uint16_t icmp6_checksum (struct icmpv6_packet packet);
uint16_t icmp6_checksum_ns (struct ns_packet packet);

// Contains just ARP header
struct __attribute__ ((packed)) arp_header{
    uint16_t hwtype;
    uint16_t prottype;
    unsigned char hw_addr_len;
    unsigned char prot_addr_len;
    uint16_t opcode;
    unsigned char source_mac[6];
    unsigned char source_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
    unsigned char filling[18]; // ARP Reply has 60 bytes, while request only 42
};

struct __attribute__ ((packed)) eth_header{
	unsigned char target_mac[6];
	unsigned char source_mac[6];
	uint16_t protocol;
};

struct __attribute__ ((packed)) arp_packet{
	struct eth_header eth;
	struct arp_header arp;
};

struct __attribute__ ((packed)) ipv6_header{
	unsigned char version_priority;
	uint8_t flow[3];
	uint16_t payload_len;
	unsigned char next_header;
	unsigned char hop_limit;
	unsigned char source_ip[IPV6_ADDR_LEN];
	unsigned char target_ip[IPV6_ADDR_LEN];
};

struct __attribute__ ((packed)) icmpv6_header{
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
};

struct __attribute__ ((packed)) icmpv6_packet{
	struct eth_header eth;
	struct ipv6_header ipv6;
	struct icmpv6_header icmpv6;
};

struct __attribute__ ((packed)) icmpv6_option{
	unsigned char type;
	unsigned char length;
	unsigned char data[6]; // Store MAC
};

// ICMPv6 header with option
struct __attribute__ ((packed))icmpv6_ns_header{
	unsigned char type;
	unsigned char code;
	uint16_t checksum;
	uint32_t reserved;
	unsigned char target_address[16];
	struct icmpv6_option option; // Support max 1 option here is enough
};

// Packet for neighbor solicitation/advertisement
struct __attribute__ ((packed)) ns_packet{
	struct eth_header eth;
	struct ipv6_header ipv6;
	struct icmpv6_ns_header icmpv6;
};

// Stores info about current interface
struct interface{
	char name[IFNAMSIZ];
	unsigned char mac[6];
	unsigned int index;
	unsigned int hostip;
	unsigned int subnet_mask;
	unsigned int network;
	std::vector<string> hostip6;
};
/*
struct victims{
	char
};
*/
class Worker{

public:
	Worker();
	void scan(char *iface, char *filename);
	void spoof(char *iface, char *protocol, unsigned int interval, char *ip1, char *mac1, char *ip2, char *mac2);
	void intercept(char *iface, char *filename);

private:
	int socketd;
	bool socket_opened;
	interface iface;
	std::map<string, std::vector<string>> mac_ip;

	// General methods
	void add(std::map<string, std::vector<string>> *dct, string key, string value);
	void parseXML(char *filename);
	void loadInterfaceInfo(char *iname);
	std::vector<string> getLocalIpv6Adresses(char *iface);
	void scanIpv4Hosts(int tries);
	void scanIpv6Hosts(int tries);
	void write(char *filename);
	void openSocket(int packetType, int socketType, int unknown);
	void closeSocket();
	void printResult();
	// IPv4
	void sendARPRequest(unsigned int ip_dst, unsigned int ip_src, unsigned char *mac_src, unsigned char *mac_dst);
	void sendARPReply(unsigned int ip_dst, unsigned int ip_src, unsigned char *mac_src, unsigned char *mac_dst);
	void receiveARPReply();
	// IPv6
	void sendIcmpv6(const char *src_mac, const char *src_ip, const char *dst_mac, const char *dst_ip);
	void sendNeighborSolicitation(const char *ip_dst, const char *ip_src, unsigned char *mac_src, unsigned char *mac_dst);
	void sendNeighborAdvertisement(unsigned char *mac_src, unsigned char *mac_dst, const char *ip_src, const char *ip_dst, unsigned char *option);
	void receiveICMPv6();
};

#endif
