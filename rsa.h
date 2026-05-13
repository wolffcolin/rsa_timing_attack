#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>
#include <string>

bool is_hex_string(const std::string& s);

struct PublicKey {
    mpz_class n;
    mpz_class e;
};

struct PrivateKey {
    mpz_class n;
    mpz_class d;
    mpz_class p;
    mpz_class q;
};

class RSA {
public:
    PublicKey load_public_key(const std::string& keyfile);
    PrivateKey load_private_key(const std::string& keyfile);
    mpz_class encrypt(const mpz_class& m, const PublicKey& key);
    mpz_class decrypt(const mpz_class& c, const PrivateKey&  key);
};

#endif