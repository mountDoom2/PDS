//============================================================================
// Name        : pds_spoof.cpp
// Author      : Milan Skala, xskala09
// Version     : 1.0
// Description : Program spoofs two victims by poisining its ARP or ND caches
//============================================================================

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <iostream>

#include "worker.h"

using namespace std;

int main (int argc, char **argv)
{
	char *interface = NULL, *protocol = NULL;
	unsigned int interval = 0;
	char *ip1 = NULL, *mac1 = NULL, *ip2 = NULL, *mac2 = NULL;
	int c, i = 0;
	// These arguments are passed as long options
	static struct option long_options[] = {
		{"victim1ip", 1, 0, 0 },
		{"victim1mac", 1, 0, 0 },
		{"victim2ip", 1, 0, 0 },
		{"victim2mac", 1, 0, 0 },
		{0, 0, 0, 0 }
	};
	opterr = 0;

	while ((c = getopt_long_only(argc, argv, "i:t:p:", long_options, &i)) != -1)
		switch (c){
			case 0:

				if (long_options[i].flag != 0){
					break;
				}
				if (strcmp(long_options[i].name, "victim1ip") == 0) ip1 = optarg;
				if (strcmp(long_options[i].name, "victim1mac") == 0) mac1 = optarg;
				if (strcmp(long_options[i].name, "victim2ip") == 0) ip2 = optarg;
				if (strcmp(long_options[i].name, "victim2mac") == 0) mac2 = optarg;
				break;
			case 'i':
				interface = optarg;
				break;
			case 't':
				interval = atoi(optarg);
				break;
			case 'p':
				protocol = optarg;
				break;
			case '?':
				if (optopt == 'i' || optopt == 'f' || optopt == 'p')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else
					fprintf (stderr, "Unknown option '%c'.\n", optopt);
				return 1;
			default:
				return 1;
		}

	if (interface == NULL){
		fprintf(stderr, "Missing '-i' option.\n");
		return 1;
	}
	if (protocol == NULL || (strcmp(protocol, "arp") != 0 && strcmp(protocol, "ndp")) != 0){
		fprintf(stderr, "Invalid protocol\n");
		return 1;
	}
	if (ip1 == NULL || mac1 == NULL || ip2 == NULL || mac2 == NULL){
		fprintf(stderr, "Missing MAC or IP address\n");
	}
	if (interval == 0){
		fprintf(stderr, "Invalid spoof interval, must be non-zero value.\n");
	}

	Worker scanner;
	scanner.spoof(interface, protocol, interval, ip1, mac1, ip2, mac2);
	return 0;
}
