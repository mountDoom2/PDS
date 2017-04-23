/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 // File contents altered by Milan Skala
*/

#include "worker.h"
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

	memcpy(ptr, &packet.ipv6.next_header, sizeof(packet.ipv6.next_header));
	ptr += sizeof(packet.ipv6.next_header);
	chksumlen += sizeof(packet.ipv6.next_header);

	memcpy(ptr, &packet.icmpv6.type, sizeof(packet.icmpv6.type));
	ptr += sizeof(packet.icmpv6.type);
	chksumlen += sizeof(packet.icmpv6.type);

	memcpy(ptr, &packet.icmpv6.code, sizeof(packet.icmpv6.code));
	ptr += sizeof(packet.icmpv6.code);
	chksumlen += sizeof(packet.icmpv6.code);

	memcpy(ptr, &packet.icmpv6.id, sizeof(packet.icmpv6.id));
	ptr += sizeof (packet.icmpv6.id);
	chksumlen += sizeof (packet.icmpv6.id);

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

	memcpy(ptr, &packet.ipv6.next_header, sizeof(packet.ipv6.next_header));
	ptr += sizeof(packet.ipv6.next_header);
	chksumlen += sizeof(packet.ipv6.next_header);

	memcpy(ptr, &packet.icmpv6.type, sizeof(packet.icmpv6.type));
	ptr += sizeof(packet.icmpv6.type);
	chksumlen += sizeof(packet.icmpv6.type);

	memcpy(ptr, &packet.icmpv6.code, sizeof(packet.icmpv6.code));
	ptr += sizeof(packet.icmpv6.code);
	chksumlen += sizeof(packet.icmpv6.code);

	memcpy(ptr, &packet.icmpv6.reserved, sizeof(packet.icmpv6.reserved));
	ptr += sizeof(packet.icmpv6.reserved);
	chksumlen += sizeof(packet.icmpv6.reserved);


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

	return checksum ((uint16_t *) buf, chksumlen);
}
