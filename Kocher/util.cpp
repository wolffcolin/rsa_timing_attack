#include <cmath>
#include <numeric>
#include <x86intrin.h>

#include "./util.h"

mpz_class square_and_multiply(mpz_class base, mpz_class exp, mpz_class mod, unsigned rounds, mpz_class& cost) {
    cost = 0;
    if (mod == 1) return 0;
    
    mpz_class result = 1;
    base = base % mod;
    unsigned roundCount = 0;
    while (exp > 0 && roundCount < rounds) {
        if (mpz_tstbit(exp.get_mpz_t(), 0)) {
            result = mul_mod_with_cost(result, base, mod, cost);
        }
        base = mul_mod_with_cost(base, base, mod, cost);
        exp >>= 1;
        roundCount++;
    }
    return result;
}

mpz_class mul_mod_with_cost(mpz_class& a, mpz_class& b, mpz_class& n, mpz_class& cost) {
    mpz_class x = a * b;
    x %= n;
    cost += mpz_sizeinbase(a.get_mpz_t(), 2) * mpz_sizeinbase(b.get_mpz_t(), 2); // cost model
    return x;
}

double variance(std::vector<long long>& vec) {
    if (vec.empty()) return 0.0;

    double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
    double mean = sum / vec.size();

    double squaredDiffSum = 0.0;
    for (const double val : vec) {
        squaredDiffSum += std::pow(val - mean, 2);
    }
    return squaredDiffSum / vec.size();
}

mpq_class variance(std::vector<mpz_class>& vec) {
    if (vec.empty()) return 0;

    mpz_class sum = 0;
    for (const mpz_class& x : vec) sum += x;
    mpq_class mean = mpq_class(sum) / vec.size();
    
    mpq_class squaredDiffSum = 0;
    for (const auto& x : vec) {
        mpq_class diff = mpq_class(x) - mean;
        squaredDiffSum += diff * diff;
    }
    return squaredDiffSum / vec.size();
}
