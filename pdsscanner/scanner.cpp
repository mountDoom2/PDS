
#include <iostream>
#include "scanner.h"


using namespace std;

NetworkScanner::NetworkScanner(){
	iname = NULL;
	socketd = -1;
	socket_opened = false;
	memset(&iface, 0, sizeof(struct interface));
	ipv6 = 0;
	recv_timeout_s = 2;
}

void NetworkScanner::scan(char *iname){
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iname);
	// Closes old socket and creates new one
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ARP);
	this->scanIpv4Hosts();
}

void NetworkScanner::sendARPRequest(unsigned int dst){
	unsigned char buffer[60];
    int src_ip = htonl(this->iface.hostip);
    int dst_ip = htonl(dst);
    //unsigned int dst = htonl(dst_ip);
	struct sockaddr_ll sll;
	memset(buffer, 0, sizeof(buffer));
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	struct ethhdr *send_req = (struct ethhdr *) buffer;
	struct arp_header *arp_req = (struct arp_header *) (buffer + 14);

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = this->iface.index;
	debug("Binding socket");
	if (bind(socketd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0){
		perror("Unable to bind socket.");
		exit(1);
	}

	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_hatype = htons(ARPHRD_ETHER);
	sll.sll_pkttype = (PACKET_BROADCAST);
	sll.sll_halen = 6;

    memset(send_req->h_dest, 0xff, 6);
    memset(arp_req->target_mac, 0x00, 6);
    memcpy(send_req->h_source, &this->iface.mac, 6);
    memcpy(arp_req->source_mac, &this->iface.mac, 6);
    memcpy(sll.sll_addr, &this->iface.mac, 6);

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->hwtype = htons(1);
    arp_req->pttype = htons(ETH_P_IP);
    arp_req->hw_addr_len = 6;
    arp_req->pt_addr_len = 4;
    arp_req->opcode = htons(0x01);

    memcpy(arp_req->source_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    int ret = sendto(socketd, buffer, 42, 0, (struct sockaddr *) &sll, sizeof(sll));
    if (ret == -1){
    	perror("Could not send ARP req");
    }

}

void NetworkScanner::scanIpv4Hosts(){
	unsigned int first = (this->iface.subnet_mask & this->iface.hostip) + 1;
	unsigned int broadcast = this->iface.hostip | (~this->iface.subnet_mask);
	debug("Net address: %u, broadcast: %u", this->iface.subnet_mask, broadcast);
	for (unsigned int target = first; target < broadcast; target++){
		this->printIPv4(target);
		this->sendARPRequest(target);
		this->receiveARPRequest();
	}
}

void NetworkScanner::receiveARPRequest(){
    debug("Receiving ARP response");

    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(this->socketd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("Could not receive ARP response");
        return;
    }

    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        //return -1;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        return;
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
}

void NetworkScanner::openSocket(int packetType, int socketType, int unknown){
	if (socket_opened)
		this->closeSocket();

	debug("Opening socket");
	socketd = socket(packetType, socketType,  htons(unknown));
	if (socketd == -1){
		perror("Unable to initialize socket");
		exit(1);
	}
	// set timeout
	struct timeval timeout;
	timeout.tv_sec = 0;//this->recv_timeout_s;
	timeout.tv_usec = 2000;
	setsockopt(socketd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));

	socket_opened = true;
}

void NetworkScanner::closeSocket(){
	if (socket_opened){
		debug("Closing socket");
		close(socketd);
	}
	socket_opened = false;
}

void NetworkScanner::loadInterfaceInfo(char *iname){
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
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
	this->iface.index = ifr.ifr_ifindex;
	debug("Successfully obtained interface index: %d", this->iface.index);
	debug("Getting source MAC address");
    if (ioctl(socketd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Unable to get source MAC address");
        exit(1);
    }

    memcpy(&this->iface.mac, ifr.ifr_hwaddr.sa_data, 6);
    debug("Source MAC address: %02X:%02X:%02X:%02X:%02X:%02X", 	this->iface.mac[0],
    															this->iface.mac[1],
																this->iface.mac[2],
																this->iface.mac[3],
																this->iface.mac[4],
																this->iface.mac[5]
    		);

    if (ioctl(socketd, SIOCGIFADDR, &ifr) == -1) {
        perror("Unable to get source IPv4 address");
        exit(1);
    }

    struct sockaddr_in *in = (struct sockaddr_in*) &(ifr.ifr_addr);
    if (ifr.ifr_addr.sa_family == AF_INET){
    	this->iface.hostip = inet_network(inet_ntoa(in->sin_addr));
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
    this->iface.subnet_mask = inet_network(inet_ntoa(inc->sin_addr))
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
