CXXFLAGS =	-O2 -g -Wall -fmessage-length=0

SRC = 		$(wildcard *.cpp)
OBJS =		$(wildcard *.o)
LIBS =		scanner.h 
TARGET =	pds_scanner


$(TARGET):	$(SRC)
	$(CXX) -o $(TARGET) $(SRC)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
