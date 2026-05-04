#include <fstream>
#include <iostream>
#include <x86intrin.h>

#include "./util.h"
#include "../rsa.h"

#define SAMPLE_SIZE 3000
#define NUM_RUNS 10
#define CSV_PATH "./samples.csv"

#define PUB_KEY "./pub.key"
#define PRI_KEY "./pri.key"
#define KEY_LEN 512

struct Sample {
    mpz_class c;
    unsigned long long cycles;
};

int main() {
    RSA rsa;
    PublicKey pubKey = rsa.load_public_key(PUB_KEY);
    PrivateKey priKey = rsa.load_private_key(PRI_KEY);

    gmp_randstate_t randState;
    gmp_randinit_default(randState);
    gmp_randseed_ui(randState, time(nullptr));

    // collect timing measurements
    std::vector<Sample> samples(SAMPLE_SIZE);
    unsigned warmUp = SAMPLE_SIZE / 100;
    unsigned int aux;
    unsigned long long start;
    unsigned long long end;
    for (unsigned i = 0; i < SAMPLE_SIZE + warmUp; i++) {
        Sample sample;

        // generate random ciphertext
        mpz_class c;
        mpz_urandomm(c.get_mpz_t(), randState, pubKey.n.get_mpz_t());
        sample.c = c;

        std::vector<unsigned long long> measurements(NUM_RUNS);
        for (unsigned j = 0; j < NUM_RUNS; j++) {
            start = __rdtscp(&aux);
            _mm_lfence();
            square_and_multiply(c, priKey.d, pubKey.n, KEY_LEN);
            _mm_lfence();
            end = __rdtscp(&aux);
            measurements.at(j) = end - start;
        }
        sample.cycles = median(measurements);

        if (i >= warmUp) samples.at(i - warmUp) = sample;
    }

    // measure hypotheses and predict bit-by-bit
    mpz_class recoveredKey = 1; // assume first key bit is 1
    mpz_ptr dPtr = priKey.d.get_mpz_t();
    for (unsigned bit = 1; bit < KEY_LEN; bit++) {
        // set hypothesis keys
        mpz_class baseHKey = 0;
        mpz_setbit(baseHKey.get_mpz_t(), (KEY_LEN - 1)); // long key with MSB = 1
        baseHKey = baseHKey | recoveredKey; // combine with recovered key so far
        mpz_class h0Key = baseHKey;
        mpz_class h1Key = baseHKey;
        mpz_setbit(h1Key.get_mpz_t(), bit); // current bit = 1

        std::vector<long long> h0Errors(SAMPLE_SIZE);
        std::vector<long long> h1Errors(SAMPLE_SIZE);
        for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
            Sample& sample = samples.at(i);
            mpz_class c = sample.c;

            std::vector<unsigned long long> h0Preds(NUM_RUNS);
            for (unsigned j = 0; j < NUM_RUNS; j++) {
                start = __rdtscp(&aux);
                _mm_lfence();
                square_and_multiply(c, h0Key, pubKey.n, bit);
                _mm_lfence();
                end = __rdtscp(&aux);
                h0Preds.at(j) = end - start;
            }
            unsigned long long h0Med = median(h0Preds);
            
            std::vector<unsigned long long> h1Preds(NUM_RUNS);
            for (unsigned j = 0; j < NUM_RUNS; j++) {
                start = __rdtscp(&aux);
                _mm_lfence();
                square_and_multiply(c, h1Key, pubKey.n, bit);
                _mm_lfence();
                end = __rdtscp(&aux);
                h1Preds.at(j) = end - start;
            }
            unsigned long long h1Med = median(h1Preds);

            h0Errors.at(i) = sample.cycles - h0Med;
            h1Errors.at(i) = sample.cycles - h1Med;
        }

        // calculate variance and predict bit
        double h0Var = variance(h0Errors);
        double h1Var = variance(h1Errors);
        std::cout << "[Bit " << bit << "] Var(h0)=" << h0Var << ", Var(h1)=" << h1Var << std::endl; 
        unsigned setBit = h0Var < h1Var;
        unsigned actualBit = mpz_tstbit(dPtr, bit);
        unsigned success = setBit == actualBit;
        if (setBit && success) {
            mpz_setbit(recoveredKey.get_mpz_t(), bit);
        }
        std::cout << "[Bit " << bit << "] " << (success ? "SUCCESS" : "FAIL") << " Predicted=" << setBit << ", Actual=" << actualBit << std::endl;
        if (!success) break;
    }

    std::cout << std::endl;
    std::cout << "Recovered key: " << recoveredKey.get_str(16) << std::endl;

    // output to csv
    std::ofstream file(CSV_PATH);
    file << "cycles" << std::endl;
    for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
        Sample sample = samples.at(i);
        file << sample.cycles << ",";
        file << std::endl;
    }
    file.close();

    return 0;
}
