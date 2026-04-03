CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS = -lgmpxx -lgmp

all: oracle timing

oracle: oracle.o rsa.o
	$(CXX) $(CXXFLAGS) -o $@ oracle.o rsa.o $(LDFLAGS)

timing: timing.o
	$(CXX) $(CXXFLAGS) -o $@ timing.o

oracle.o: oracle.cpp rsa.h
	$(CXX) $(CXXFLAGS) -c oracle.cpp -o oracle.o

rsa.o: rsa.cpp rsa.h
	$(CXX) $(CXXFLAGS) -c rsa.cpp -o rsa.o

timing.o: timing.cpp
	$(CXX) $(CXXFLAGS) -c timing.cpp -o timing.o

clean:
	rm -f oracle timing oracle.o rsa.o timing.o

.PHONY: all clean