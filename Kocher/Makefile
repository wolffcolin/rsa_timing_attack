CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic -I..
LDLIBS = -lgmpxx -lgmp

TARGET = main.exe

SRCS = main.cpp util.cpp ../rsa.cpp
OBJS = main.o util.o rsa.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.cpp util.h ../rsa.h
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

util.o: util.cpp util.h
	$(CXX) $(CXXFLAGS) -c util.cpp -o util.o

rsa.o: ../rsa.cpp ../rsa.h
	$(CXX) $(CXXFLAGS) -c ../rsa.cpp -o rsa.o

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
