
#include <iostream>
#include "scanner.h"


using namespace std;

NetworkScanner::NetworkScanner(){
	interface = NULL;
	socketd = -1;
	socket_opened = false;
	ipv4 = 0;
	ipv6 = 0;
	memset(&mac, 0, 6);
	memset(&ifr, 0, sizeof(struct ifreq));
}

void NetworkScanner::scan(char *iname){
	struct arp_header arp;
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iname);
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
	debug("Successfully obtained interface index: %d", ifr.ifr_ifindex);
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
    	ipv4 = in->sin_addr.s_addr;
    }else{
    	fprintf(stderr, "Not an IPv4\n");
    	exit(1);
    }
    debug("Successfully got source IPv4 address: %s", inet_ntoa(in->sin_addr));
}

void NetworkScanner::write(char *filename){
	cout << "Filename: " << filename << endl;
}
