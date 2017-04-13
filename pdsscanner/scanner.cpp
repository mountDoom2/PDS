
#include <iostream>
#include "scanner.h"


using namespace std;

NetworkScanner::NetworkScanner(){
	interface = NULL;
	socketd = -1;
	socket_opened = false;
	iface_index = 0;
	ipv4 = 0;
	ipv6 = 0;
	subnet_mask = 0;
	memset(&mac, 0, 6);
	memset(&ifr, 0, sizeof(struct ifreq));
}

void NetworkScanner::scan(char *iname){
	struct arp_header arp;
	unsigned int subnet_address;
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iname);
	// Closes old socket and creates new one
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ARP);
	//this->buildARPRequest(&arp);

	subnet_address = this->ipv4 & this->subnet_mask;
	debug("Net address: %u", subnet_address);
	for (unsigned int address = 3232249956; address; address++){
		// Skip broadcast
		if (address + 1 == 0)
			break;
		this->printIPv4(address);
		this->buildARPRequest(&arp, address);
	    while(10) {
	        int r = read_arp(socketd);
	        if (r == 0) {
	            debug("Got reply, break out");
	            break;
	        }
	    }
	}

}

void NetworkScanner::buildARPRequest(struct arp_header *arp, unsigned int dst_ip){
	struct sockaddr_ll sll;
    unsigned char buffer[60];
    memset(buffer, 0, sizeof(buffer));
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = iface_index;
	debug("Binding socket");
	if (bind(socketd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0){
		perror(" Could not bind");
		exit(1);
	}

	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_hatype = htons(ARPHRD_ETHER);
	sll.sll_pkttype = (PACKET_BROADCAST);
	sll.sll_halen = 6;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + 14);

    memset(send_req->h_dest, 0xff, 6);
    memset(arp_req->target_mac, 0x00, 6);
    memcpy(send_req->h_source, mac, 6);
    memcpy(arp_req->source_mac, mac, 6);
    memcpy(sll.sll_addr, mac, 6);

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->hwtype = htons(1);
    arp_req->pttype = htons(ETH_P_IP);
    arp_req->hw_addr_len = 6;
    arp_req->pt_addr_len = 4;
    arp_req->opcode = htons(0x01);
    memcpy(arp_req->source_ip, &ipv4, sizeof(uint32_t));
    //uint32_t dst_ip = 3232249956;
    //uint32_t dst_ip = 1681434816;
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));
    //arp->target_ip = &;
    //arp->tpa[0] = {192, 168, 56, 100};

    int ret = sendto(socketd, buffer, 42, 0, (struct sockaddr *) &sll, sizeof(sll));
    if (ret == -1){
    	perror("Could not send ARP req");
    }

}

void NetworkScanner::openSocket(int packetType, int socketType, int unknown){
	if (!socket_opened)
		this->closeSocket();

	debug("Opening socket");
	socketd = socket(packetType, socketType,  htons(unknown));
	if (socketd == -1){
		perror("Unable to initialize socket");
		exit(1);
	}
	socket_opened = true;
}

void NetworkScanner::closeSocket(){
	if (socket_opened){
		debug("Closing socket");
		close(socketd);
	}
}

void NetworkScanner::loadInterfaceInfo(char *iname){
	debug("Getting information of interface '%s'", iname)
	if (strlen(iname) > (IFNAMSIZ - 1)){
		perror("Interface name is too long");
		exit(1);
	}
	debug("Copying interface name to ifreq structure");
	strncpy(ifr.ifr_name, iname, IFNAMSIZ);
	debug("Getting interface index");
	if (ioctl(socketd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Unable to get interface index");
        exit(1);
    }
	iface_index = ifr.ifr_ifindex;
	debug("Successfully obtained interface index: %d", iface_index);
	debug("Getting source MAC address");
    if (ioctl(socketd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Unable to get source MAC address");
        exit(1);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    debug("Source MAC address: %02X:%02X:%02X:%02X:%02X:%02X", 	mac[0],
																mac[1],
																mac[2],
																mac[3],
																mac[4],
																mac[5]
    		);

    if (ioctl(socketd, SIOCGIFADDR, &ifr) == -1) {
        perror("Unable to get source IPv4 address");
        exit(1);
    }

    struct sockaddr_in *in = (struct sockaddr_in*) &(ifr.ifr_addr);
    if (ifr.ifr_addr.sa_family == AF_INET){
    	ipv4 = htonl(in->sin_addr.s_addr);
    }else{
    	fprintf(stderr, "Not an IPv4\n");
    	exit(1);
    }
    debug("Successfully got source IPv4 address: %s", inet_ntoa(in->sin_addr));

    if (ioctl(socketd, SIOCGIFNETMASK , &ifr) == -1) {
        perror("Unable to get subnet mask");
        exit(1);
    }
    struct sockaddr_in *inc = (struct sockaddr_in*) &(ifr.ifr_netmask);
    subnet_mask = inet_network(inet_ntoa(inc->sin_addr));
    debug("Successfully got subnet mask: %s", inet_ntoa(inc->sin_addr));
}

void NetworkScanner::printIPv4(unsigned int ip){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

unsigned int NetworkScanner::reorderIPv4(unsigned int ip){
    return (ip & 0xFF) | ((ip >> 8) & 0xFF) | ((ip >> 16) & 0xFF) | ((ip >> 24) & 0xFF);
}


void NetworkScanner::write(char *filename){
	cout << "Filename: " << filename << endl;
}


#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

int read_arp(int fd)
{


    debug("read_arp");
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        return -1;
    }

    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        return -1;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        return -1;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;

    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->source_ip, sizeof(uint32_t));
    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->source_mac[0],
          arp_resp->source_mac[1],
          arp_resp->source_mac[2],
          arp_resp->source_mac[3],
          arp_resp->source_mac[4],
          arp_resp->source_mac[5]);

    ret = 0;

    return ret;
}
