#ifndef UTIL_HPP
#define UTIL_HPP

#include <gmpxx.h>

mpz_class square_and_multiply(mpz_class c, mpz_class d, mpz_class n, unsigned& cost);

mpz_class mult_mod(mpz_class a, mpz_class b, mpz_class n, unsigned& cost);

#endif // UTIL_HPP
