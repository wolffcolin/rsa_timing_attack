#include <iostream>

#include "./nbyte.hpp"

#define N 4

// Calculate a^b mod n based on the square and multiply algorithm.
nbyte<N>* expMod(nbyte<N>* a, nbyte<N>* b, nbyte<N>* n) {
	nbyte<N> f(1);
	for (int i = N-1; i >= 0; --i) {
		for (int j = 7; j >= 0; --j) {
		}
	}
	return nullptr;
}

int main() {
	nbyte<2> a({0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1});
	nbyte<2> b({0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1});
	nbyte<2> c({0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0});
	std::cout << a << std::endl;
	std::cout << b << std::endl;
	std::cout << (a+b) << std::endl;
	std::cout << a.shiftLeft1() << std::endl;
	std::cout << (a*c) << std::endl;
	std::cout << "b << 1: " << b.shiftLeft1() << std::endl;
	std::cout << "b*c: " << (b*c) << std::endl;

	return 0;
}