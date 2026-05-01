#include <chrono>
#include <fstream>
#include <iostream>
#include <vector>

#include "./util.h"
#include "../rsa.h"

#define SAMPLE_SIZE 10000 
#define CSV_PATH "./samples.csv"

#define PUB_KEY "./pub.key"
#define PRI_KEY "./pri.key"
#define N_SIZE 512

struct Sample {
    mpz_class c;
    double elapsed;
    unsigned simCost;
};

int main() {
    RSA rsa;
    PublicKey pubKey = rsa.load_public_key(PUB_KEY);
    PrivateKey priKey = rsa.load_private_key(PRI_KEY);

    gmp_randstate_t randState;
    gmp_randinit_default(randState);
    gmp_randseed_ui(randState, time(nullptr));

    std::vector<Sample> samples(SAMPLE_SIZE);
    for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
        Sample sample;

        // generate random ciphertext
        mpz_class c;
        mpz_urandomm(c.get_mpz_t(), randState, pubKey.n.get_mpz_t());
        sample.c = c;
        
        auto startTime = std::chrono::steady_clock::now();
        square_and_multiply(c, priKey.d, pubKey.n, sample.simCost);
        auto endTime = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = endTime - startTime;
        sample.elapsed = elapsed.count();

        samples.at(i) = sample;
    }

    // output to csv
    std::ofstream file(CSV_PATH);
    file << "elapsed,simCost" << std::endl;
    for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
        Sample sample = samples.at(i);
        file << sample.elapsed << "," << sample.simCost << "," << std::endl;
    }
    file.close();

    return 0;
}
