#include "./util.h"

mpz_class square_and_multiply(mpz_class c, mpz_class d, mpz_class n, unsigned& cost) {
    cost = 0;
    mp_bitcnt_t bits = mpz_sizeinbase(d.get_mpz_t(), 2);
    mpz_class m = c;
    for (mp_bitcnt_t i = bits; i > 0; i--) {
        m = mult_mod(m, m, n, cost);

        // timing leak here
        if (mpz_tstbit(d.get_mpz_t(), i - 1)) {
            m = mult_mod(m, c, n, cost);
        }
    }
    return m;
}

mpz_class mult_mod(mpz_class a, mpz_class b, mpz_class n, unsigned& cost) {
    mpz_class x = a * b;
    mpz_class k = x / n;
    x = x - k * n;
    cost += 1 + k.get_ui(); // cost model
    return x;
}
