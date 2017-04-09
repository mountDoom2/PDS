CXXFLAGS =	-O2 -g -Wall -fmessage-length=0

OBJS =		PDS_1.o

LIBS =

TARGET =	PDS_1

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
