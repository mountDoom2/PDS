CXXFLAGS =	-O0 -g -Wall -fmessage-length=0 -pthread -std=c++11 -I/usr/include/libxml2/
SRC = 		$(wildcard *.cpp)
OBJS =		$(wildcard *.o)
LIBS =		scanner.h 
TARGET =	pds_scanner


$(TARGET):	$(SRC)
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS) -lxml2

all:	$(TARGET)

debug: $(SRC)
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS) -lxml2 -DDEBUG
clean:
	rm -f $(OBJS) $(TARGET)
