
#include <iostream>
#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <net/if.h>

using namespace std;

NetworkScanner::NetworkScanner(){
	interface = NULL;
}

void NetworkScanner::scan(char *iface){

	cout << "Scanning " << iface << endl;
}

void NetworkScanner::write(){
	cout << "No file" << endl;
}

void NetworkScanner::write(char *filename){
	cout << "Filename: " << filename << endl;
}
