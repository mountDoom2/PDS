
#include <iostream>
#include "scanner.h"


using namespace std;
int _interrupted = 0;

char *string2char(string str){
	char * writable = new char[str.size() + 1];
	std::copy(str.begin(), str.end(), writable);
	writable[str.size()] = '\0'; // don't forget the terminating 0
	return writable;
}

NetworkScanner::NetworkScanner(){
	socketd = -1;
	socket_opened = false;
	memset(&iface, 0, sizeof(struct interface));
	recv_timeout_s = 2;
}


void int_handler(int s){
	_interrupted = 1;
	printf("INTERRUPTED\n");
}

void NetworkScanner::scan(char *iname){
	struct sigaction sig_handler;
	sig_handler.sa_handler = int_handler;
	sigemptyset(&sig_handler.sa_mask);
	sig_handler.sa_flags = 0;
	sigaction(SIGINT, &sig_handler, NULL);

	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iname);
	// Closes old socket and creates new one
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ARP);
	this->scanIpv4Hosts(3);
	this->openSocket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->scanIpv6Hosts(3);
	this->printResult();
}

void NetworkScanner::printResult(){
	for (auto const& x : this->mac_ip)
	{
	    cout << x.first << ": ";
	    for (auto i = x.second.begin(); i != x.second.end(); ++i){
	        cout << *i << ", ";
		}
	    cout << endl;
	}
}
/**
 * Send ARP request to desired address
 */
void NetworkScanner::sendARPRequest(unsigned int dst){
	struct arp_packet arp_request;
	struct sockaddr_ll sll;
    uint32_t src_ip = htonl(this->iface.hostip);
    uint32_t dst_ip = htonl(dst);

    memset(&arp_request, 0, sizeof(arp_request));
    memset(&sll, 0, sizeof(struct sockaddr_ll));

    // Configure sll
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = this->iface.index;
	sll.sll_hatype = htons(ARPHRD_ETHER);
	sll.sll_pkttype = (PACKET_BROADCAST);
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_halen = MAC_LENGTH;

	// Configure ethernet header
	memset(arp_request.eth.target_mac, 0xFF, MAC_LENGTH);
	memcpy(arp_request.eth.source_mac, this->iface.mac, MAC_LENGTH);
	arp_request.eth.protocol = htons(ETH_P_ARP);

	// Configure arp header
	arp_request.arp.hwtype = htons(ARPOP_REQUEST);
	arp_request.arp.prottype = htons(ETH_P_IP);
	arp_request.arp.hw_addr_len = MAC_LENGTH;
	arp_request.arp.prot_addr_len = 4;
	arp_request.arp.opcode = htons(ARPOP_REQUEST);
	memcpy(arp_request.arp.source_mac, this->iface.mac, MAC_LENGTH);
	memcpy(arp_request.arp.source_ip, &src_ip, sizeof(uint32_t));
	memset(arp_request.arp.source_mac, 0xFF, MAC_LENGTH);
	memcpy(arp_request.arp.target_ip, &dst_ip, sizeof(uint32_t));

	// Bind socket
	if (bind(socketd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0){
		perror("Unable to bind socket.");
		return;
	}

    int ret = sendto(socketd, &arp_request, 42, 0, (struct sockaddr *) &sll, sizeof(sll));
    if (ret == -1){
    	perror("Could not send ARP req");
    }

}

void NetworkScanner::scanIpv4Hosts(int tries){
	unsigned int first = (this->iface.subnet_mask & this->iface.hostip) + 1;
	unsigned int broadcast = this->iface.hostip | (~this->iface.subnet_mask);
	debug("Net address: %u, broadcast: %u", this->iface.subnet_mask, broadcast);
	std::thread receiver([=] {receiveARPRequest();});

	for (int i = 0; i < tries; i++){
		for (unsigned int target = first; target < broadcast; target++){
			if (_interrupted){
				break;
			}
			usleep(50);
			this->sendARPRequest(target);
			// delay between arp requests
		}
		usleep(150);
	}
	receiver.join();
}

std::vector<string> NetworkScanner::getLocalIpv6Adresses(char *iface){
	vector<string> addresses;

	struct ifaddrs *ifa=NULL,*ifEntry=NULL;
	void *addPtr = NULL;
	int rc = 0;
	char addressBuffer[INET6_ADDRSTRLEN];

	rc = getifaddrs(&ifa);
	if (rc==0) {
		for(ifEntry=ifa; ifEntry!=NULL; ifEntry=ifEntry->ifa_next) {
			if(ifEntry->ifa_addr->sa_data == NULL) {
				continue;
			}
			if(ifEntry->ifa_addr->sa_family==AF_INET6 && (iface == NULL || !strcmp(ifEntry->ifa_name, iface))) {
				 addPtr = &((struct sockaddr_in6 *)ifEntry->ifa_addr)->sin6_addr;
			}
			else
				continue;

			const char *a = inet_ntop(ifEntry->ifa_addr->sa_family,
						  addPtr,
						  addressBuffer,
						  sizeof(addressBuffer));
			if(a != NULL) {
					addresses.push_back(string(a));
			}
		}
	}
	freeifaddrs(ifa);

	return addresses;
}

void NetworkScanner::scanIpv6Hosts(int tries){
	if (!this->iface.hostip6.size())
		return;

	std::thread receiver([=] {receiveICMPv6();});
	usleep(50);
	// Set destination MAC address to multicast
	char dst_mac[6];
	memset(dst_mac, 0, 6);
	dst_mac[0] = 0x33;
	dst_mac[1] = 0x33;
	dst_mac[5] = 0x01;

	char dst_ip[IPV6_ADDR_LEN];

    for (int i = 0; i < tries; i++){
		for(vector<string>::const_iterator it=this->iface.hostip6.begin(); it != this->iface.hostip6.end(); it++) {
			if (_interrupted){
				break;
			}

			char *src_ip = string2char(*it);
			memset(dst_ip, 0, IPV6_ADDR_LEN);
			memcpy(dst_ip, "ff02::1", 8);
			this->sendIcmpv6((char*)this->iface.mac, src_ip, dst_mac, dst_ip);
			usleep(50);
			memset(dst_ip, 0, IPV6_ADDR_LEN);
			memcpy(dst_ip, "ff02::2", 8);
			this->sendIcmpv6((char*)this->iface.mac, src_ip, dst_mac, dst_ip);
			//this->sendNS(address, "ff02::1");
			delete[] src_ip;
		}
		usleep(100);
    }
    receiver.join();
/*
	std::thread receiver([=] {receiveICMPv6();});
	usleep(50);
    for (int i = 0; i < tries; i++){
		for(vector<string>::const_iterator it=this->iface.hostip6.begin(); it != this->iface.hostip6.end(); it++) {
			char *src_ip = string2char(*it);
			this->sendIcmpv6(src_ip, "ff02::1");
			//this->sendNS(address, "ff02::1");
			delete[] address;
		}
		usleep(500);
    }
    receiver.join();
    */
}

void NetworkScanner::receiveICMPv6(){
	struct icmpv6_packet *ping_response;
	uint16_t frame[IP_MAXPACKET];
	unsigned int bytes, i;
	int sckt = -1;
	socklen_t sendersize;
	struct timeval timeout;
	struct sockaddr sender;

	memset(frame, 0, IP_MAXPACKET * sizeof(uint16_t));
	memset(&ping_response, 0, sizeof(struct icmpv6_packet));
	memset(&sender, 0, sizeof(struct sockaddr));

	sendersize = sizeof(sender);

	sckt = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  	timeout.tv_sec = 0;
  	timeout.tv_usec = 500;
  	setsockopt(sckt, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));
  	i = 0;
	while (i <= 1500){
		if (_interrupted){
			break;
		}
		  i += 1;
	      memset (frame, 0, IP_MAXPACKET * sizeof (uint8_t));
	      memset (&sender, 0, sizeof (sender));

	      if ((bytes = recvfrom (sckt, frame, IP_MAXPACKET, 0, (struct sockaddr *) &sender, &sendersize)) < 0) {
	    	  if (! (i % 500)){
	    		  debug("Nothing received");
	    	  }
	    	  continue;
	      }

	      if (bytes < sendersize){
	    	  debug("Short packet");
	    	  continue;
	      }
	      ping_response = (icmpv6_packet*) frame;

	      // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
	      if (htons(ping_response->eth.protocol) != ETH_P_IPV6){
	    	  debug("Received not-IPv6 packet: %02x, size %u", htons(ping_response->eth.protocol), bytes );
	    	  continue;
	      }


	      if (ping_response->ipv6.next_header != IPPROTO_ICMPV6){
	    	  debug("Received IPv6 packet, but it is not a ICMPv6 response.");
	    	  continue;
	      }
	      // Got ping response
	      debug("Got ping response");
	      char src_ip[25];
	      memset(src_ip, 0, 25);
	      inet_ntop (AF_INET6, ping_response->ipv6.source_ip, src_ip, INET6_ADDRSTRLEN);
	        i = 0;
	        usleep(100);

			char tmp[15];

			for (int i = 0; i < 6; i++){
			    sprintf(&tmp[2*i], "%02x", ping_response->eth.source_mac[i]);
			}

			string _mac(tmp);
			_mac.insert(4,1,'.');
			_mac.insert(9,1,'.');
			string _ip6(reinterpret_cast<char*>(src_ip));
			this->add(&(this->mac_ip), _mac, _ip6);
	      }
	if (sckt > 0)
		close(sckt);

}

void NetworkScanner::sendIcmpv6(const char *src_mac, const char *src_ip,
		const char *dst_mac, const char *dst_ip){

	struct icmpv6_packet ping;
	memset(&ping, 0, sizeof(struct icmpv6_packet));

	// Configure eth header
	// Set MAC to multicast
	memcpy(ping.eth.target_mac, dst_mac, MAC_LENGTH);
	memcpy(ping.eth.source_mac, src_mac, MAC_LENGTH);
	ping.eth.protocol = htons(ETH_P_IPV6);

	// Configure ipv6 header
	ping.ipv6.version_priority = 0x6F;
	*ping.ipv6.flow = 0x3C;
	ping.ipv6.payload_len = htons(8);
	ping.ipv6.next_header = IPPROTO_ICMPV6;
	ping.ipv6.hop_limit = 0xFF; // Set hop limit to maximum
	// Convert ipv6 strings to bytes
	inet_pton (AF_INET6, src_ip, ping.ipv6.source_ip);
	inet_pton (AF_INET6, dst_ip, ping.ipv6.target_ip);

	// Configure icmpv6 header
	ping.icmpv6.type = ICMP6_ECHO_REQUEST;
	ping.icmpv6.code = 0; // echo request
	ping.icmpv6.id = htons(::getpid());
	ping.icmpv6.seq = htons(0);
	ping.icmpv6.checksum = icmp6_checksum(ping);


	  struct sockaddr_ll device;
	  memset (&device, 0, sizeof (device));
	  device.sll_ifindex = this->iface.index;
	  device.sll_family = AF_PACKET;
	  memcpy (device.sll_addr, this->iface.mac, 6 * sizeof (char));
	  device.sll_halen = 6;


	  if (sendto (this->socketd, &ping, sizeof(ping), 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
	        perror ("sendto() failed ");
	        exit (EXIT_FAILURE);
	      }
}

void NetworkScanner::receiveARPRequest(){
	struct arp_packet arp;
	struct timeval timeout;
	int sckt, i;
	memset(&arp, 0, sizeof(struct arp_packet));

    debug("Receiving ARP responses");
	if ((sckt = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ARP))) < 0){
		perror("Unable to initialize socket");
		return;
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = 300;
	setsockopt(sckt, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));

	i = 0;
    while (i < 500){
		if (_interrupted){
			break;
		}
    	i += 1;
		int length = recvfrom(sckt, &arp, 60, 0, NULL, NULL);
		if (length <= 0) {
			continue;
		}

		if (ntohs(arp.eth.protocol) != PROTO_ARP) {
			debug("Not an ARP packet");
			continue;
		}
		if (ntohs(arp.arp.opcode) != ARP_REPLY) {
			debug("Not an ARP reply");
			continue;
		}
		// Got ARP reply, reset counter
		i = 0;
		//usleep(50);

		// Store mac and ipv4
		char tmp[15];

		for (int i = 0; i < 6; i++){
		    sprintf(&tmp[2*i], "%02x", arp.arp.source_mac[i]);
		}

		string _mac(tmp);
		_mac.insert(4,1,'.');
		_mac.insert(9,1,'.');


		struct in_addr sender_a;
		memset(&sender_a, 0, sizeof(struct in_addr));
		memcpy(&sender_a.s_addr, &(arp.arp.source_ip), sizeof(uint32_t));
		string _ip(reinterpret_cast<char*>(inet_ntoa(sender_a)));
		this->add(&(this->mac_ip), _mac, _ip);
    }
    if (sckt > 0)
    	close(sckt);
}

void NetworkScanner::add(std::map<string, std::vector<string>> *dct, string key, string value){

	std::map<string, std::vector<string>> &_dict = *dct;

	if (_dict.count(key)){
		if (find(_dict[key].begin(), _dict[key].end(),value) == _dict[key].end()){
			_dict[key].push_back(value);
		}

	}else{
		_dict[key];
		_dict[key].push_back(value);
	}
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
	timeout.tv_usec = 100;
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

    /////////////////////////////////
    ///////// LOAD IPv6 info ////////
    /////////////////////////////////
    this->iface.hostip6 = this->getLocalIpv6Adresses(iname);

}

void NetworkScanner::printIPv4(unsigned int ip){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void NetworkScanner::write(char *filename){
	cout << "Filename: " << filename << endl;

	xmlNodePtr node = NULL;
	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	xmlNodePtr devices = xmlNewNode(NULL, BAD_CAST "devices");
    xmlDocSetRootElement(doc, devices);

	for (auto const& x : this->mac_ip)
	{
	    node = xmlNewChild(devices, NULL, BAD_CAST "host", NULL);
	    xmlNewProp(node, BAD_CAST "mac", BAD_CAST x.first.c_str());

	    for (auto i = x.second.begin(); i != x.second.end(); ++i){
			xmlNewChild(node, NULL, BAD_CAST ((signed int)i->find('.') == -1 ? "ipv6" : "ipv4"),
                    BAD_CAST i->c_str());
		}
	    cout << endl;
	}

    xmlSaveFormatFileEnc(filename, doc, "UTF-8", 1);
}
/*
int NetworkScanner::sendNS(char* src_ip, char* dst_ip){
	struct icmpv6_header packet;
	memset(&packet, 0, sizeof(struct icmpv6_header));

	packet.type = 135; // Neighbor Solicitation
	packet.code = 0;
	packet.checksum = 0;
	memcpy(packet.target, dst_ip, 16);

	packet.eth.type = 1; // Source link-layer
	packet.eth.length = 1;
	memcpy(packet.eth.mac, this->iface.name, 6);


}
*/
// Definition of pktinfo6 created from definition of in6_pktinfo in netinet/in.h.
// This should remove "redefinition of in6_pktinfo" errors in some linux variants.
/*
typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
};
*/
/*
int NetworkScanner::sendNA(char* src_ip, char* dst_ip)
{
  int NA_HDRLEN = sizeof (struct nd_neighbor_advert);  // Length of NA message header
  int optlen = 8; // Option Type (1 byte) + Length (1 byte) + Length of MAC address (6 bytes)
  debug("a");
  int i, sd, status, ifindex, cmsglen, psdhdrlen;
  struct addrinfo hints;
  struct addrinfo *res;
  struct sockaddr_in6 src, dst;
  struct nd_neighbor_advert *na;
  uint8_t *outpack, *options, *psdhdr, hoplimit;
  struct msghdr msghdr = {};
  struct ifreq ifr;
  struct cmsghdr *cmsghdr1, *cmsghdr2;
  pktinfo6 *pktinfo;
  struct iovec iov[2];

  cmsghdr2 = (struct cmsghdr*) malloc(sizeof(struct cmsghdr));
  memset(cmsghdr2, 0, sizeof(struct cmsghdr));
  // Allocate memory for various arrays.

  psdhdr = new uint8_t[IP_MAXPACKET]();
  memset(psdhdr, 0, IP_MAXPACKET);
  options = new uint8_t[optlen]();
  memset(options, 0, optlen);
  outpack = new uint8_t[IP_MAXPACKET]();
  memset(outpack, 0, IP_MAXPACKET);
  memset(&msghdr, 0, sizeof(struct msghdr));

  // Interface to send packet through.
  debug("b");
  //strcpy (interface, this->iface.name);
  debug("c");
  // Source (node sending advertisement) IPv6 link-local address: you need to fill this out
  //strcpy (source, src_ip);
  debug("d");
  // Destination IPv6 address either:
  // 1) unicast address of node which sent solicitation, or if the
  // solicitation came from the unspecified address (::), use the
  // 2) IPv6 "all nodes" link-local multicast address (ff02::1).
  // You need to fill this out.
  //strcpy (target, dst_ip);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;
  debug("e");
  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  debug("e1");
  memset (&src, 0, sizeof (src));
  debug("e2");
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  debug("e3");
  memcpy (psdhdr, src.sin6_addr.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header
  debug("e4");
  freeaddrinfo (res);
  debug("f");
  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (dst_ip, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  debug("g");
  memset (&dst, 0, sizeof (dst));
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  memcpy (psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header
  freeaddrinfo (res);
  debug("h");
  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up advertising node's (i.e., source's) interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", this->iface.name);
  debug("i");

  // Copy advertising MAC address into options buffer.
  options[0] = 2;           // Option Type - "target link layer address" (Section 4.6 of RFC 4861)
  options[1] = optlen / 8;  // Option Length - units of 8 octets (RFC 4861)
  for (i=0; i<6; i++) {
    options[i+2] = (uint8_t) this->iface.mac[i];
  }

  // Report advertising node MAC address to stdout.
  printf ("Advertising node's MAC address for interface %s is ", this->iface.name);
  for (i=0; i<5; i++) {
    printf ("%02x:", options[i+2]);
  }
  printf ("%02x\n", options[5+2]);

  // Find interface index from interface name.
  // This will be put in cmsghdr data in order to specify the interface we want to use.
  ifindex = this->iface.index;
  printf ("Advertising node's index for interface %s is %i\n", this->iface.name, ifindex);

  // Define first part of buffer outpack to be a neighbor advertisement struct.
  na = (struct nd_neighbor_advert *) outpack;
  debug("j");
  memset (na, 0, sizeof (struct nd_neighbor_advert));
  debug("k");
  // Populate icmp6_hdr portion of neighbor advertisement struct.
  na->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;  // 136 (RFC 4861)
  na->nd_na_hdr.icmp6_code = 0;              // zero for neighbor advertisement (RFC 4861)
  na->nd_na_hdr.icmp6_cksum = htons(0);      // zero when calculating checksum
  // Set R/S/O flags as: R=0, S=1, O=1. Set reserved to zero (RFC 4861)
  na->nd_na_flags_reserved = htonl((1 << 30) + (1 << 29));
  na->nd_na_target = src.sin6_addr;          // Target address (as type in6_addr)
  debug("l");
  // Append options to end of neighbor advertisement struct.
  memcpy (outpack + NA_HDRLEN, options, optlen * sizeof (uint8_t));
  debug("m");
  // Need a pseudo-header for checksum calculation. Define length. (RFC 2460)
  // Length = source IP (16 bytes) + destination IP (16 bytes)
  //        + upper layer packet length (4 bytes) + zero (3 bytes)
  //        + next header (1 byte)
  psdhdrlen = 16 + 16 + 4 + 3 + 1 + NA_HDRLEN + optlen;

  // Prepare msghdr for sendmsg().
  memset (&msghdr, 0, sizeof (struct msghdr));
  debug("n");
  msghdr.msg_name = &dst;  // Destination IPv6 address as struct sockaddr_in6
  msghdr.msg_namelen = sizeof (dst);
  memset (&iov, 0, sizeof (struct iovec));
  debug("o");
  iov[0].iov_base = (uint8_t *) outpack;  // Point msghdr to buffer outpack
  iov[0].iov_len = NA_HDRLEN + optlen;
  msghdr.msg_iov = iov;                 // scatter/gather array
  msghdr.msg_iovlen = 1;                // number of elements in scatter/gather array

  // Tell msghdr we're adding cmsghdr data to change hop limit and specify interface.
  // Allocate some memory for our cmsghdr data.
  cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (pktinfo));
  msghdr.msg_control = new char[cmsglen];// allocate_ustrmem (cmsglen);
  msghdr.msg_controllen = cmsglen;
  debug("p");
  // Change hop limit to 255 as required for neighbor advertisement (RFC 4861).
  hoplimit = 255u;
  cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
  cmsghdr1->cmsg_level = IPPROTO_IPV6;
  cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit
  cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
  *(CMSG_DATA (cmsghdr1)) = hoplimit;  // Copy pointer to int hoplimit
  debug("q");
  // Specify source interface index for this packet via cmsghdr data.
  cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
  debug("q1");
  cmsghdr2->cmsg_level = IPPROTO_IPV6;
  debug("q11");
  cmsghdr2->cmsg_type = IPV6_PKTINFO;  // We want to specify interface here
  debug("q12");
  cmsghdr2->cmsg_len = CMSG_LEN (sizeof (pktinfo6));
  debug("q2");
  pktinfo = (pktinfo6 *) CMSG_DATA (cmsghdr2);
  debug("q3");
  pktinfo->ipi6_ifindex = ifindex;
  debug("r");
  // Compute ICMPv6 checksum (RFC 2460).
  // psdhdr[0 to 15] = source IPv6 address, set earlier.
  // psdhdr[16 to 31] = destination IPv6 address, set earlier.
  psdhdr[32] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[33] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[34] = (NA_HDRLEN + optlen)  / 256;  // Upper layer packet length
  psdhdr[35] = (NA_HDRLEN + optlen)  % 256;  // Upper layer packet length
  psdhdr[36] = 0;  // Must be zero
  psdhdr[37] = 0;  // Must be zero
  psdhdr[38] = 0;  // Must be zero
  psdhdr[39] = IPPROTO_ICMPV6;
  memcpy (psdhdr + 40, outpack, (NA_HDRLEN + optlen) * sizeof (uint8_t));
  debug("s");
  na->nd_na_hdr.icmp6_cksum = checksum ((uint16_t *) psdhdr, psdhdrlen);
  debug("t");
  printf ("Checksum: %x\n", ntohs (na->nd_na_hdr.icmp6_cksum));

  // Send packet.
  if (sendmsg (sd, &msghdr, 0) < 0) {
    perror ("sendmsg() failed ");
    exit (EXIT_FAILURE);
  }
  close (sd);


  return (EXIT_SUCCESS);
}
*/
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

uint16_t icmp6_checksum (struct icmpv6_packet packet)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (128 bits)
	memcpy(ptr, packet.ipv6.source_ip, IPV6_ADDR_LEN);
	ptr += IPV6_ADDR_LEN;
	chksumlen += IPV6_ADDR_LEN;

	// Copy destination IP address into buf (128 bits)
	memcpy (ptr, packet.ipv6.target_ip, IPV6_ADDR_LEN);
	ptr += IPV6_ADDR_LEN;
	chksumlen += IPV6_ADDR_LEN;

	// Copy Upper Layer Packet length into buf (32 bits).
	// Should not be greater than 65535 (i.e., 2 bytes).
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = 8 / 256;
	ptr++;
	*ptr = 8 % 256;
	ptr++;
	chksumlen += 4;

	// Copy zero field to buf (24 bits)
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 3;

	// Copy next header field to buf (8 bits)
	memcpy(ptr, &packet.ipv6.next_header, sizeof(packet.ipv6.next_header));
	ptr += sizeof(packet.ipv6.next_header);
	chksumlen += sizeof(packet.ipv6.next_header);

	// Copy ICMPv6 type to buf (8 bits)
	memcpy(ptr, &packet.icmpv6.type, sizeof(packet.icmpv6.type));
	ptr += sizeof(packet.icmpv6.type);
	chksumlen += sizeof(packet.icmpv6.type);

	// Copy ICMPv6 code to buf (8 bits)
	memcpy(ptr, &packet.icmpv6.code, sizeof(packet.icmpv6.code));
	ptr += sizeof(packet.icmpv6.code);
	chksumlen += sizeof(packet.icmpv6.code);

	// Copy ICMPv6 ID to buf (16 bits)
	memcpy(ptr, &packet.icmpv6.id, sizeof(packet.icmpv6.id));
	ptr += sizeof (packet.icmpv6.id);
	chksumlen += sizeof (packet.icmpv6.id);

	// Copy ICMPv6 sequence number to buff (16 bits)
	memcpy(ptr, &packet.icmpv6.seq, sizeof(packet.icmpv6.seq));
	ptr += sizeof(packet.icmpv6.seq);
	chksumlen += sizeof(packet.icmpv6.seq);

	// Copy ICMPv6 checksum to buf (16 bits)
	// Zero, since we don't know it yet.
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy ICMPv6 payload to buf
	return checksum ((uint16_t *) buf, chksumlen);
}



