//============================================================================
// Name        : PDS_1.cpp
// Author      : Milan Skala
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C, Ansi-style
//============================================================================

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "scanner.h"

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
				abort();
		}

	if (filename == NULL){
		fprintf (stderr, "Missing '-f' option.\n");
		return 1;
	}
	if (interface == NULL){
		fprintf (stderr, "Missing '-i' option.\n");
		return 1;

	}

	NetworkScanner scanner;
	scanner.scan(interface);
	scanner.write(filename);
	return 0;
}
