CXXFLAGS =	-O0 -g -Wall -fmessage-length=0 -pthread -std=c++11 -I/usr/include/libxml2/
SRC = 		$(wildcard *.cpp)
OBJS =		$(wildcard *.o) 
TARGET =	pds_scanner
DEP = scanner.cpp

all: pds-scanner pds-spoof

pds-scanner: pds_scanner.cpp
	$(CXX) -o pds-scanner pds_scanner.cpp $(DEP) $(CXXFLAGS) -lxml2

pds-spoof: pds_spoof.cpp
	$(CXX) -o pds-spoof pds_spoof.cpp $(DEP) $(CXXFLAGS) -lxml2

debug: $(SRC)
	$(CXX) -o pds-spoof pds_spoof.cpp $(CXXFLAGS) -lxml2 -DDEBUG
clean-scanner:
	rm -f pds-scanner
clean-spoof:
	rm -f pds-spoof
	
