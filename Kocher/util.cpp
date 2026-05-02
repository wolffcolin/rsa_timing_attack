#include <x86intrin.h>
#include "./util.h"

mpz_class square_and_multiply(mpz_class y, mpz_class x, mpz_class n, unsigned& cost) {
    // cost = 0;
    mpz_ptr xPtr = x.get_mpz_t();
    mp_bitcnt_t w = mpz_sizeinbase(xPtr, 2);
    mpz_class sk = 1;
    mpz_class Rk = 1;
    for (mp_bitcnt_t k = 0; k < w; k++) {
        if (mpz_tstbit(xPtr, k)) {
            Rk = sk * y;
            Rk %= n; 
        }
        else {
            Rk = sk;
        }
        sk = (Rk * Rk) % n;
    }
    return Rk;
}

mpz_class mult_mod(mpz_class a, mpz_class b, mpz_class n, unsigned& cost) {
    mpz_class x = a * b;
    mpz_class k = x / n;
    x = x - k * n;
    cost += 1 + mpz_sizeinbase(k.get_mpz_t(), 2); // cost model: 1 multiply + k subtractions
    return x;
}
