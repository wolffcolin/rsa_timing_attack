#ifndef UTIL_HPP
#define UTIL_HPP

#include <vector>
#include <gmpxx.h>

mpz_class square_and_multiply(mpz_class base, mpz_class exp, mpz_class mod, unsigned rounds);

unsigned long long median(std::vector<unsigned long long>& vec);

double variance(std::vector<long long>& vec);

#endif // UTIL_HPP
