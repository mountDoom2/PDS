CXXFLAGS =	-O2 -g -Wall -fmessage-length=0
SRC = 		$(wildcard *.cpp)
OBJS =		$(wildcard *.o)
LIBS =		scanner.h 
TARGET =	pds_scanner


$(TARGET):	$(SRC)
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS)

all:	$(TARGET)

debug: $(SRC)
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS) -DDEBUG
clean:
	rm -f $(OBJS) $(TARGET)
