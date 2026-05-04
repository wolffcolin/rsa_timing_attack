#ifndef UTIL_HPP
#define UTIL_HPP

#include <vector>
#include <gmpxx.h>

mpz_class square_and_multiply(mpz_class base, mpz_class exp, mpz_class mod, unsigned rounds, mpz_class& cost);

mpz_class mul_mod_with_cost(mpz_class& a, mpz_class& b, mpz_class& n, mpz_class& cost);

template<typename T>
T median(std::vector<T>& vec) {
    if (vec.empty()) return 0;

    size_t n = vec.size() / 2;
    std::nth_element(vec.begin(), vec.begin() + n, vec.end()); // get nth element if vec was sorted
    T median = vec.at(n);
    if (vec.size() % 2 == 0) {
        // find max of elements in left half
        auto max_it = std::max_element(vec.begin(), vec.begin() + n);
        median = (*max_it + median) / 2;
    }
    return median;
}

double variance(std::vector<long long>& vec);

mpq_class variance(std::vector<mpz_class>& vec);

#endif // UTIL_HPP
