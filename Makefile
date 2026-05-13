CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic
LDLIBS = -lgmpxx -lgmp

all: gen_key oracle timing

gen_key: keygen.cpp
	$(CXX) $(CXXFLAGS) -o $@ keygen.cpp $(LDLIBS)

oracle: oracle.o rsa.o
	$(CXX) $(CXXFLAGS) -o $@ oracle.o rsa.o $(LDLIBS)

timing: timing.o
	$(CXX) $(CXXFLAGS) -o $@ timing.o

oracle.o: oracle.cpp rsa.h
	$(CXX) $(CXXFLAGS) -c oracle.cpp -o oracle.o

rsa.o: rsa.cpp rsa.h
	$(CXX) $(CXXFLAGS) -c rsa.cpp -o rsa.o

timing.o: timing.cpp
	$(CXX) $(CXXFLAGS) -c timing.cpp -o timing.o

clean:
	rm -f gen_key oracle timing oracle.o rsa.o timing.o

tidy:
	rm -f oracle.o rsa.o timing.o

.PHONY: all clean tidy