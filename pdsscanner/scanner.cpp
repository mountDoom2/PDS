
#include <iostream>
#include "scanner.h"


using namespace std;

char *string2char(string str){
	char * writable = new char[str.size() + 1];
	std::copy(str.begin(), str.end(), writable);
	writable[str.size()] = '\0'; // don't forget the terminating 0
	return writable;
}
// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (8 + payloadlen) / 256;
  ptr++;
  *ptr = (8 + payloadlen) % 256;
  ptr++;
  chksumlen += 4;

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy ICMPv6 type to buf (8 bits)
  memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
  ptr += sizeof (icmp6hdr.icmp6_type);
  chksumlen += sizeof (icmp6hdr.icmp6_type);

  // Copy ICMPv6 code to buf (8 bits)
  memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
  ptr += sizeof (icmp6hdr.icmp6_code);
  chksumlen += sizeof (icmp6hdr.icmp6_code);

  // Copy ICMPv6 ID to buf (16 bits)
  memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
  ptr += sizeof (icmp6hdr.icmp6_id);
  chksumlen += sizeof (icmp6hdr.icmp6_id);

  // Copy ICMPv6 sequence number to buff (16 bits)
  memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
  ptr += sizeof (icmp6hdr.icmp6_seq);
  chksumlen += sizeof (icmp6hdr.icmp6_seq);

  // Copy ICMPv6 checksum to buf (16 bits)
  // Zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy ICMPv6 payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

NetworkScanner::NetworkScanner(){
	socketd = -1;
	socket_opened = false;
	memset(&iface, 0, sizeof(struct interface));
	recv_timeout_s = 2;
}

void NetworkScanner::scan(char *iname){
	this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->loadInterfaceInfo(iname);
	// Closes old socket and creates new one
	//this->openSocket(AF_PACKET, SOCK_RAW, ETH_P_ARP);
	//this->scanIpv4Hosts(2);
	this->openSocket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
	this->scanIpv6Hosts(3);
}

void NetworkScanner::sendARPRequest(unsigned int dst){
	unsigned char buffer[60];
    int src_ip = htonl(this->iface.hostip);
    int dst_ip = htonl(dst);
	struct sockaddr_ll sll;
	memset(buffer, 0, sizeof(buffer));
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	struct ethhdr *send_req = (struct ethhdr *) buffer;
	struct arp_header *arp_req = (struct arp_header *) (buffer + 14);

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = this->iface.index;
	//debug("Binding socket");
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

void NetworkScanner::scanIpv4Hosts(int tries){
	unsigned int first = (this->iface.subnet_mask & this->iface.hostip) + 1;
	unsigned int broadcast = this->iface.hostip | (~this->iface.subnet_mask);
	debug("Net address: %u, broadcast: %u", this->iface.subnet_mask, broadcast);
	std::thread receiver([=] {receiveARPRequest();}); //NetworkScanner::receiveARPRequest);
	for (int i = 0; i < tries; i++){
		for (unsigned int target = first; target < broadcast; target++){
			this->sendARPRequest(target);
			// delay between arp requests
			usleep(50);
		}
	}
	receiver.join();

	for (auto const& x : this->mac_ipv4)
	{
	    cout << x.first << ": ";
	    for (auto i = x.second.begin(); i != x.second.end(); ++i){
	        cout << *i << ", ";
		}
	    cout << endl;
	}
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

	std::thread receiver([=] {receiveICMPv6();}); //NetworkScanner::receiveARPRequest);
    for (int i = 0; i < tries; i++){
		for(vector<string>::const_iterator it=this->iface.hostip6.begin(); it != this->iface.hostip6.end(); it++) {
			char *address = string2char(*it);
			this->sendIcmpv6(address, "ff02::1");
			//this->sendNS(address, "ff02::1");
			cout << address << endl;
			delete[] address;
		}
		usleep(500);
    }
    receiver.join();
	for (auto const& x : this->mac_ipv6)
	{
	    cout << x.first << ": ";
	    for (auto i = x.second.begin(); i != x.second.end(); ++i){
	        cout << *i << ", ";
		}
	    cout << endl;
	}
}

void NetworkScanner::receiveICMPv6(){
	  uint8_t *recv_ether_frame;
	  socklen_t fromlen;
	  struct sockaddr from;
	  int recvsd;
	  struct ip6_hdr *recv_iphdr;
	  struct icmp6_hdr *recv_icmphdr;
	  char *rec_ip;

	  rec_ip = new char[INET6_ADDRSTRLEN]();
	  memset(rec_ip, 0, sizeof(char) * INET6_ADDRSTRLEN);

	  recv_ether_frame = new uint8_t[IP_MAXPACKET]();
	  memset(recv_ether_frame, 0, sizeof(uint8_t) * IP_MAXPACKET);

	  recv_iphdr = (struct ip6_hdr *) (recv_ether_frame + 14);
	  recv_icmphdr = (struct icmp6_hdr *) (recv_ether_frame + 14 + 40);
      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);
      int bytes;
	  recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
	  struct timeval timeout;
	  	timeout.tv_sec = 0;
	  	timeout.tv_usec = 100;
	  	setsockopt(recvsd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));
	  int i = 0;
	  while (1){
		  if (i > 1500)
			  break;
	      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
	      memset (&from, 0, sizeof (from));
	      fromlen = sizeof (from);
	      i += 1;
	      if ((bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) > 0) {
	      // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
	      if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IPV6) &&
	         (recv_iphdr->ip6_nxt == IPPROTO_ICMPV6) && (recv_icmphdr->icmp6_type == ICMP6_ECHO_REPLY)) {
	        // Extract source IP address from received ethernet frame.
	        if (inet_ntop (AF_INET6, &(recv_iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL) {
	        	perror("NOPE");
	        }
	        // Report source IPv6 address and time for reply.
	        printf ("response - %s\n", rec_ip);
	        i = 0;
	        usleep(100);
	        unsigned char *source_mac;
	        source_mac = recv_ether_frame + 6;

			char tmp[15];

			for (int i = 0; i < 6; i++){
			    sprintf(&tmp[2*i], "%02x", source_mac[i]);
			}

			string _mac(tmp);
			_mac.insert(4,1,'.');
			_mac.insert(9,1,'.');
			string _ip6(reinterpret_cast<char*>(rec_ip));
			//cout << "MAC STRING: " << _mac << endl;
			//cout << "IP6 STRING: " << _ip6 << endl;
			//this->add(this->mac_ipv4, _mac, _ip4);

			if (this->mac_ipv6.count(_mac)){
				if (find(this->mac_ipv6[_mac].begin(), this->mac_ipv6[_mac].end(),_ip6) == this->mac_ipv6[_mac].end()){
				   this->mac_ipv6[_mac].push_back(_ip6);
				}

			}else{
				this->mac_ipv6[_mac];
				this->mac_ipv6[_mac].push_back(_ip6);
			}

	        //break;  // Break out of Receive loop.
	      }
	    }  // End of Receive loop.
	  }
}

void NetworkScanner::sendIcmpv6(char* src, char* dst){
	debug ("wow1");
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;
	debug("wow2");
	if (getaddrinfo (dst, NULL, &hints, &res) != 0) {
		perror("Unable to get addrinfo");
	    exit(1);
	}
	debug ("wow3");
	struct icmp6_hdr send_icmphdr, *recv_icmphdr;

	struct ip6_hdr send_iphdr;
	send_iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	  // Payload length (16 bits): ICMP header + ICMP data
	  send_iphdr.ip6_plen = htons (8); // 8 = ICMP header length
	  debug ("wow5");
	  // Next header (8 bits): 58 for ICMP
	  send_iphdr.ip6_nxt = IPPROTO_ICMPV6;

	  // Hop limit (8 bits): default to maximum value
	  send_iphdr.ip6_hops = 255;

	  // Source IPv6 address (128 bits)
	  if (inet_pton (AF_INET6, src, &(send_iphdr.ip6_src)) != 1) {
	    perror("inet_pton error src.");
	    exit (1);
	  }

	  if (inet_pton (AF_INET6, dst, &(send_iphdr.ip6_dst)) != 1) {
	    perror("inet_pton error dst.");
	    exit (1);
	  }
	  debug ("wow6");

	  // Message Type (8 bits): echo request
	  send_icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

	  // Message Code (8 bits): echo request
	  send_icmphdr.icmp6_code = 0;

	  // Identifier (16 bits): usually pid of sending process - pick a number
	  send_icmphdr.icmp6_id = htons (1000);

	  // Sequence Number (16 bits): starts at 0
	  send_icmphdr.icmp6_seq = htons (0);

	  // ICMP header checksum (16 bits): set to 0 when calculating checksum
	  send_icmphdr.icmp6_cksum = 0;
	  send_icmphdr.icmp6_cksum = icmp6_checksum (send_iphdr, send_icmphdr, NULL, 0);


	  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
	  int frame_length = 6 + 6 + 2 + 40 + 8;
	  uint8_t *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
	  uint8_t dst_m[6];
	  send_ether_frame = new uint8_t[IP_MAXPACKET]();
	  memset(send_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
	  recv_ether_frame = new uint8_t[IP_MAXPACKET]();
	  memset(recv_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
	  memset(dst_m, 0, 6);
	  dst_m[0] = 0x33;
	  dst_m[1] = 0x33;
	  dst_m[5] = 0x01;
	//dst_m[0]= 51;
	//	dst_m[1]= 51;
	  // Destination and Source MAC addresses
	  memcpy (send_ether_frame, dst_m, 6 * sizeof (uint8_t));
	  memcpy (send_ether_frame + 6, this->iface.mac, 6 * sizeof (uint8_t));
	  // Next is ethernet type code (ETH_P_IPV6 for IPv6).
	  // http://www.iana.org/assignments/ethernet-numbers
	  send_ether_frame[12] = ETH_P_IPV6 / 256;
	  send_ether_frame[13] = ETH_P_IPV6 % 256;

	  // Next is ethernet frame data (IPv6 header + ICMP header + ICMP data).

	  // IPv6 header
	  memcpy (send_ether_frame + 14, &send_iphdr, 40 * sizeof (uint8_t));

	  // ICMP header
	  memcpy (send_ether_frame + 14 + 40, &send_icmphdr, 8 * sizeof (uint8_t));

	  // ICMP data
	  memcpy (send_ether_frame + 14 + 40 + 8, "", 0 * sizeof (uint8_t));

	  struct ip6_hdr *recv_iphdr;
	  // Cast recv_iphdr as pointer to IPv6 header within received ethernet frame.
	  recv_iphdr = (struct ip6_hdr *) (recv_ether_frame + 14);

	  // Cast recv_icmphdr as pointer to ICMP header within received ethernet frame.
	  recv_icmphdr = (struct icmp6_hdr *) (recv_ether_frame + 14 + 40);

	  struct sockaddr_ll device;
	  memset (&device, 0, sizeof (device));
	  device.sll_ifindex = this->iface.index;

	  device.sll_family = AF_PACKET;
	  memcpy (device.sll_addr, this->iface.mac, 6 * sizeof (char));
	  device.sll_halen = 6;
	  debug ("wow15");
	  if (sendto (this->socketd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
	        perror ("sendto() failed ");
	        exit (EXIT_FAILURE);
	      }
}

void NetworkScanner::receiveARPRequest(){
    debug("Receiving ARP responses");
	int socketd2 = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ARP));
	if (socketd2 < 0){
		perror("Unable to initialize socket");
		return;
	}
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 100;
	setsockopt(socketd2, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout,sizeof(struct timeval));

	struct mac_ip;


    int max = 100;
    int i = 0;
    while (1){
    	if (i == max)
    		break;
    	i += 1;
    	printf("i: %d\n", i);
		unsigned char buffer[BUF_SIZE];
		int length = recvfrom(socketd2, buffer, BUF_SIZE, 0, NULL, NULL);
		if (length <= 0) {
			continue;
		}

		struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
		struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
		if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
			debug("Not an ARP packet");
			continue;
			//return -1;
		}
		if (ntohs(arp_resp->opcode) != ARP_REPLY) {
			debug("Not an ARP reply");
			continue;
			//return;
		}
		i = 0;
		struct in_addr sender_a;

		memset(&sender_a, 0, sizeof(struct in_addr));
		memcpy(&sender_a.s_addr, arp_resp->source_ip, sizeof(uint32_t));
		printf("Sender IP: %s", inet_ntoa(sender_a));

		printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
			  arp_resp->source_mac[0],
			  arp_resp->source_mac[1],
			  arp_resp->source_mac[2],
			  arp_resp->source_mac[3],
			  arp_resp->source_mac[4],
			  arp_resp->source_mac[5]);
		usleep(50);
		char tmp[15];

		for (int i = 0; i < 6; i++){
		    sprintf(&tmp[2*i], "%02x", arp_resp->source_mac[i]);
		}

		string _mac(tmp);
		_mac.insert(4,1,'.');
		_mac.insert(9,1,'.');
		string _ip4(reinterpret_cast<char*>(inet_ntoa(sender_a)));
		cout << "MAC STRING: " << _mac << endl;
		cout << "IP4 STRING: " << _ip4 << endl;
		//this->add(this->mac_ipv4, _mac, _ip4);

		if (this->mac_ipv4.count(_mac)){
			if (find(this->mac_ipv4[_mac].begin(), this->mac_ipv4[_mac].end(),_ip4) == this->mac_ipv4[_mac].end()){
			   this->mac_ipv4[_mac].push_back(_ip4);
			}

		}else{
			this->mac_ipv4[_mac];
			this->mac_ipv4[_mac].push_back(_ip4);
		}

    }
}

void NetworkScanner::add(std::map<string, std::vector<string>> *_map, string key, string value){
}/*
	if (_map.count(key)){
		if (find(_map[key].begin(), _map[key].end(),value) == _map[key].end()){
			_map[key].push_back(value);
		}

	}else{
		_map[key];
		_map[key].push_back(value);
	}
}
*/
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
}

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




