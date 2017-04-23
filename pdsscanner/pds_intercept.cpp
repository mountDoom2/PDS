//============================================================================
// Name        : pds_intercept.cpp
// Author      : Milan Skala, xskala09
// Version     : 0.1
// Description : Program loads XML document with marked victims and intercepts their communication
//============================================================================

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "worker.h"

int main (int argc, char **argv)
{
	char *filename = NULL;
	char *interface = NULL;
	int c;

	opterr = 0;

	while ((c = getopt (argc, argv, "i:f:")) != -1)
		switch (c){
			case 'i':
				interface = optarg;
				break;
			case 'f':
				filename = optarg;
				break;
			case '?':
				if (optopt == 'i' || optopt == 'f')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				return 1;
			default:
				fprintf (stderr, "Unknown option '%c'.\n", optopt);
				return 1;
		}

	if (filename == NULL){
		fprintf (stderr, "Missing '-f' option.\n");
		return 1;
	}
	if (interface == NULL){
		fprintf (stderr, "Missing '-i' option.\n");
		return 1;

	}

	Worker scanner;
	scanner.intercept(interface, filename);
	return 0;
}
