TARGET=topnviewerd
SRCS	=$(wildcard *.cpp)
OBJECTS	=$(SRCS:.cpp=.o)

CXXFLAGS+=-I/root/android/sysroot/include
LDFLAGS+=-L/root/android/sysroot/lib

LDLIBS += -lpcap

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(TARGET_ARCH) $(OBJECTS) $(LDLIBS) -o $(TARGET)

main.o: main.cpp
dot11.o: dot11.cpp dot11.h
radiotap.o: radiotap.cpp radiotap.h
gdot11hdr.o: gdot11hdr.cpp gdot11hdr.h
gmac.o: gmac.cpp gmac.h
gqosnullhdr.o: gqosnullhdr.cpp gqosnullhdr.h
gradiotabhdr.o: gradiotabhdr.cpp gradiotabhdr.h
gssg.o: gssg.cpp gssg.h
gtrace.o: gtrace.cpp gtrace.h

clean:
	rm -f $(TARGET)
	rm -f *.o

