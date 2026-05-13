#include <cmath>
#include <numeric>
#include <x86intrin.h>

#include "./util.h"

mpz_class square_and_multiply(mpz_class base, mpz_class exp, mpz_class mod, unsigned rounds) {
    if (mod == 1) return 0;
    
    mpz_class result = 1;
    base = base % mod;
    unsigned roundCount = 0;
    while (exp > 0 && roundCount < rounds) {
        if (mpz_tstbit(exp.get_mpz_t(), 0)) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
        roundCount++;
    }
    return result;
}

unsigned long long median(std::vector<unsigned long long>& vec) {
    if (vec.empty()) return 0;

    size_t n = vec.size() / 2;
    std::nth_element(vec.begin(), vec.begin() + n, vec.end()); // get nth element if vec was sorted
    long long median = vec.at(n);
    if (vec.size() % 2 == 0) {
        // find max of elements in left half
        auto max_it = std::max_element(vec.begin(), vec.begin() + n);
        median = (*max_it + median) / 2;
    }
    return median;
}

double variance(std::vector<long long>& vec) {
    if (vec.size() < 2) return 0.0;

    double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
    double mean = sum / vec.size();

    double squaredDiffSum = 0.0;
    for (double val : vec) {
        squaredDiffSum += std::pow(val - mean, 2);
    }
    return squaredDiffSum / (vec.size());
}
