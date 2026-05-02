#include <fstream>
#include <iostream>
#include <vector>
#include <x86intrin.h>

#include "./util.h"
#include "../rsa.h"

#define SAMPLE_SIZE 10000 
#define CSV_PATH "./samples.csv"

#define PUB_KEY "./pub.key"
#define PRI_KEY "./pri.key"

struct Sample {
    mpz_class c;
    unsigned long long cycles;
    // unsigned simCost;
};

int main() {
    RSA rsa;
    PublicKey pubKey = rsa.load_public_key(PUB_KEY);
    PrivateKey priKey = rsa.load_private_key(PRI_KEY);

    gmp_randstate_t randState;
    gmp_randinit_default(randState);
    gmp_randseed_ui(randState, time(nullptr));

    std::vector<Sample> samples(SAMPLE_SIZE);
    unsigned warmUp = SAMPLE_SIZE / 100;
    for (unsigned i = 0; i < SAMPLE_SIZE + warmUp; i++) {
        Sample sample;

        // generate random ciphertext
        mpz_class c;
        mpz_urandomm(c.get_mpz_t(), randState, pubKey.n.get_mpz_t());
        sample.c = c;

        unsigned int aux;
        unsigned long long start = __rdtscp(&aux);
        _mm_lfence();

        // square_and_multiply(c, priKey.d, pubKey.n, sample.simCost);
        rsa.decrypt(c, priKey);

        _mm_lfence();
        unsigned long long end = __rdtscp(&aux);
        sample.cycles = end - start;

        if (i >= warmUp) samples.at(i - warmUp) = sample;
    }

    // output to csv
    std::ofstream file(CSV_PATH);
    // file << "cycles,simCost" << std::endl;
    file << "cycles" << std::endl;
    for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
        Sample sample = samples.at(i);
        file << sample.cycles << ",";
        // file << sample.simCost << ",";
        file << std::endl;
    }
    file.close();

    return 0;
}
