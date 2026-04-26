#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <x86intrin.h>
#include <stdlib.h>
//#include "eea.c"

#define ITERATIONS 100
#define NEIGHBORHOOD 512

//#define DEBUG


// A compare algorithm for quicksort
int compare_long_long(const void *a, const void *b) {
    const unsigned long long *val_a = (const unsigned long long *)a;
    const unsigned long long *val_b = (const unsigned long long *)b;

    if (*val_a < *val_b) return -1;
    if (*val_a > *val_b) return 1;
    return 0;
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
	BN_rshift(guess, rsa->q, 257);
	BN_lshift(guess, guess, 257);

        printf("\nq:             ");
	BN_print_fp(stdout, rsa->q);
	printf("\n");

	printf("guess:         ");
	BN_print_fp(stdout, guess);
	printf("\n");


        // For storing timings
       	unsigned long long cycles[NEIGHBORHOOD][ITERATIONS] = {0};

// *********************************************************************************************
//      This is the start of actual decryption
//
//
	// Loop for timings
	for (unsigned long variations = 0; variations < NEIGHBORHOOD; variations++) {
                BN_zero(guessneighbor);
                BN_set_word(guessneighbor, variations);
                BN_add(guessneighbor, guess, guessneighbor);
                BN_mod_mul(cipherguess, guessneighbor, Rprime, rsa->n, ctx);

                printf("guessneighbor: ");
                BN_print_fp(stdout, guessneighbor);
                printf("\n");

                // Write cipherguess to ciphertext array (0 padded)
                memset(ciphertext, 0, (rsa_size - BN_num_bytes(cipherguess)));
		int bytes_written = BN_bn2bin(
			cipherguess, ciphertext + (rsa_size - BN_num_bytes(cipherguess)));
// #ifdef DEBUG
			printf("\n Ciphertext: ");
			for (int i = 0; i < rsa_size; i++) {
				printf("%02x", ciphertext[i]);
			}
			printf("\n");
// #endif

		for (int i = 0; i < ITERATIONS; i++) {
			// Timing code from https://blog.codingconfessions.com/p/rdtsc
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
        qsort(cycles, ITERATIONS * NEIGHBORHOOD, sizeof(unsigned long long), compare_long_long);
	printf("cycles: %llu, %llu, %llu\n", ((unsigned long long *) cycles)[0], ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD/2], ((unsigned long long *) cycles)[ITERATIONS*NEIGHBORHOOD-1]);


// // *********************************************************************************************
// //      Second Guess
// //
// //
// 	BN_rshift(guess, rsa->q, 256);
// 	BN_lshift(guess, guess, 256);

// 	printf("guess: ");
// 	BN_print_fp(stdout, guess);
// 	printf("\n");
// 	for (unsigned long variations = 0; variations < 1; variations++) {
// 		memset(ciphertext, 0, rsa_size);
//                 BN_zero(guessneighbor);
//                 BN_set_word(guessneighbor, variations);
//                 BN_add(guessneighbor, guess, guessneighbor);
//                 BN_mod_mul(cipherguess, guessneighbor, Rprime, rsa->n, ctx);

//                 printf("guessneighbor: ");
//                 BN_print_fp(stdout, guessneighbor);
//                 printf("\n");

// 		int bytes_written = BN_bn2bin(
// 			cipherguess, ciphertext + (rsa_size - BN_num_bytes(cipherguess)));
// #ifdef DEBUG
// 			printf("\n Ciphertext: ");
// 			for (int i = 0; i < rsa_size; i++) {
// 				printf("%02x", ciphertext[i]);
// 			}
// 			printf("\n");
// #endif

// 		for (int i = 0; i < ITERATIONS; i++) {
// 			// Timing code from https://blog.codingconfessions.com/p/rdtsc
// 			unsigned int auxCPUID1, auxCPUID2;
// 			unsigned long long start, end;
// 			_mm_lfence();
// 			start = __rdtscp(&auxCPUID1);
// 			// Decrypt
// 			// RSA_NO_PADDING as used in the paper
// 			int result = RSA_private_decrypt(rsa_size, ciphertext,
// 							 decrypted, rsa,
// 							 RSA_NO_PADDING);
// 			_mm_lfence();
// 			end = __rdtscp(&auxCPUID2);

// #ifdef DEBUG
// 			printf("\nPlaintext: ");
// 			for (int i = 0; i < rsa_size; i++) {
// 				printf("%02x ", decrypted[i]);
// 			}
// 			printf("\n");
// #endif

// 			if (result == -1) {
// 				ERR_print_errors_fp(stderr);
// 			} else {
// 				cycles[0][i] = (end - start);
// #ifdef DEBUG
// 				printf("Decryption successful!\n");
// 				printf("Cycles taken: %llu\n", (end - start));
// 				printf("CPUIDs: %d, %d\n", auxCPUID1, auxCPUID2);
// #endif
// 			}
// 		}
// 	}
//         qsort(cycles, ITERATIONS * NEIGHBORHOOD, sizeof(long long), compare_long_long);
// 	printf("cycles: %d, %d, %d\n", cycles[0][0], cycles[0][50], cycles[0][ITERATIONS-1]);


// // *********************************************************************************************
// //      Third Guess
// //
// //
// 	BN_rshift(guess, rsa->q, 256);
// 	BN_lshift(guess, guess, 1);
//         BN_one(guessneighbor);
//         BN_add(guess, guess, guessneighbor);
//         BN_lshift(guess, guess, 255);


// 	printf("guess: ");
// 	BN_print_fp(stdout, guess);
// 	printf("\n");
// 	for (unsigned long variations = 0; variations < 1; variations++) {
// 		memset(ciphertext, 0, rsa_size);
//                 BN_zero(guessneighbor);
//                 BN_set_word(guessneighbor, variations);
//                 BN_add(guessneighbor, guess, guessneighbor);
//                 BN_mod_mul(cipherguess, guessneighbor, Rprime, rsa->n, ctx);

//                 printf("guessneighbor: ");
//                 BN_print_fp(stdout, guessneighbor);
//                 printf("\n");

// 		int bytes_written = BN_bn2bin(
// 			cipherguess, ciphertext + (rsa_size - BN_num_bytes(cipherguess)));
// #ifdef DEBUG
// 			printf("\n Ciphertext: ");
// 			for (int i = 0; i < rsa_size; i++) {
// 				printf("%02x", ciphertext[i]);
// 			}
// 			printf("\n");
// #endif

// 		for (int i = 0; i < ITERATIONS; i++) {
// 			// Timing code from https://blog.codingconfessions.com/p/rdtsc
// 			unsigned int auxCPUID1, auxCPUID2;
// 			unsigned long long start, end;
// 			_mm_lfence();
// 			start = __rdtscp(&auxCPUID1);
// 			// Decrypt
// 			// RSA_NO_PADDING as used in the paper
// 			int result = RSA_private_decrypt(rsa_size, ciphertext,
// 							 decrypted, rsa,
// 							 RSA_NO_PADDING);
// 			_mm_lfence();
// 			end = __rdtscp(&auxCPUID2);

// #ifdef DEBUG
// 			printf("\nPlaintext: ");
// 			for (int i = 0; i < rsa_size; i++) {
// 				printf("%02x ", decrypted[i]);
// 			}
// 			printf("\n");
// #endif

// 			if (result == -1) {
// 				ERR_print_errors_fp(stderr);
// 			} else {
// 				cycles[0][i] = (end - start);
// #ifdef DEBUG
// 				printf("Decryption successful!\n");
// 				printf("Cycles taken: %llu\n", (end - start));
// 				printf("CPUIDs: %d, %d\n", auxCPUID1, auxCPUID2);
// #endif
// 			}
// 		}
// 	}
//         qsort(cycles, ITERATIONS * NEIGHBORHOOD, sizeof(long long), compare_long_long);
// 	printf("cycles: %d, %d, %d\n", cycles[0][0], cycles[0][50], cycles[0][ITERATIONS-1]);
	



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