
#ifndef SCANNER_H
#define SCANNER_H

class NetworkScanner{
	char *interface;

public:
	NetworkScanner();
	void scan(char *iface);
	void write();
	void write(char *filename);
};


#endif
