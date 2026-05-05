#include <fstream>
#include <iostream>
#include <sys/resource.h>
#include <x86intrin.h>

#include "./util.h"
#include "../rsa.h"

#define SAMPLE_SIZE 5000
#define NUM_RUNS 10
#define CSV_PATH "./samples.csv"

#define PUB_KEY "./pub.key"
#define PRI_KEY "./pri.key"
#define KEY_LEN 512

struct Sample {
    mpz_class c;
    unsigned long long cycles;
    mpz_class costModel;
};

int main() {
    struct sched_param param;	
    param.sched_priority = 90; // high real-time priority
	if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
		std::cerr << "Failed to set scheduler" << std::endl;
	}
    if (setpriority(PRIO_PROCESS, 0, -20) == -1) {
        std::cerr << "Failed to set process priority" << std::endl;
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(3, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        std::cerr << "Failed to pin CPU" << std::endl;
    }

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
            _mm_lfence();
            start = __rdtscp(&aux);
            square_and_multiply(c, priKey.d, pubKey.n, KEY_LEN, sample.costModel);
            end = __rdtscp(&aux);
            _mm_lfence();
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
        // std::vector<mpz_class> h0CostErrors(SAMPLE_SIZE);
        // std::vector<mpz_class> h1CostErrors(SAMPLE_SIZE);
        for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
            Sample& sample = samples.at(i);
            mpz_class c = sample.c;

            std::vector<unsigned long long> h0Preds(NUM_RUNS);
            mpz_class h0CostModel;
            for (unsigned j = 0; j < NUM_RUNS; j++) {
                _mm_lfence();
                start = __rdtscp(&aux);
                square_and_multiply(c, h0Key, pubKey.n, bit + 1, h0CostModel);
                end = __rdtscp(&aux);
                _mm_lfence();
                h0Preds.at(j) = end - start;
            }
            unsigned long long h0Med = median(h0Preds);
            
            std::vector<unsigned long long> h1Preds(NUM_RUNS);
            mpz_class h1CostModel;
            for (unsigned j = 0; j < NUM_RUNS; j++) {
                _mm_lfence();
                start = __rdtscp(&aux);
                square_and_multiply(c, h1Key, pubKey.n, bit + 1, h1CostModel);
                end = __rdtscp(&aux);
                _mm_lfence();
                h1Preds.at(j) = end - start;
            }
            unsigned long long h1Med = median(h1Preds);

            h0Errors.at(i) = sample.cycles - h0Med;
            h1Errors.at(i) = sample.cycles - h1Med;
            // h0CostErrors.at(i) = sample.costModel - h0CostModel;
            // h1CostErrors.at(i) = sample.costModel - h1CostModel;
        }

        // calculate variance and predict bit
        double h0Var = variance(h0Errors);
        double h1Var = variance(h1Errors);
        // mpq_class h0CostVar = variance(h0CostErrors);
        // mpq_class h1CostVar = variance(h1CostErrors);
        std::cout << "[Bit " << bit << "] Var(h0)=" << h0Var << ", Var(h1)=" << h1Var << std::endl; 
        unsigned setBit = h1Var < h0Var;
        unsigned actualBit = mpz_tstbit(dPtr, bit);
        unsigned success = setBit == actualBit;
        if (setBit) mpz_setbit(recoveredKey.get_mpz_t(), bit);
        std::cout << "[Bit " << bit << "] " << (success ? "SUCCESS" : "FAIL") << " Predicted=" << setBit << ", Actual=" << actualBit << std::endl;
        if (!success) break;
    }

    std::cout << std::endl;
    std::cout << "Recovered key: " << recoveredKey.get_str(16) << std::endl;

    // output to csv
    std::ofstream file(CSV_PATH);
    file << "cycles,costModel" << std::endl;
    for (unsigned i = 0; i < SAMPLE_SIZE; i++) {
        Sample& sample = samples.at(i);
        file << sample.cycles << ",";
        file << sample.costModel << ",";
        file << std::endl;
    }
    file.close();

    return 0;
}
