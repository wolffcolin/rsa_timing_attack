#include <iostream>
#include <string>
#include <fstream>
#include <gmpxx.h>
#include <cerrno>
#include <stdexcept>
#include <unistd.h>
#include <sstream>
#include "rsa.h"

// cli utility to encrypt and decrypt text with RSA implementation
// can be used to generate ciphertext for timing attack

mpz_class text_to_mpz(const std::string& plaintext) {
    mpz_class m;
    mpz_import(m.get_mpz_t(), plaintext.size(), 1, 1, 1, 0, plaintext.data());

    return m;
}

std::string mpz_to_text(const mpz_class& m) {
    size_t count = 0;
    void* buf = mpz_export(nullptr, &count, 1, 1, 1, 0, m.get_mpz_t());

    std::string recovered(static_cast<char*>(buf), count);

    free(buf);

    return recovered;
}

void write_mpz(const std::string& filename, const mpz_class& contents) {
    std::ofstream out(filename);
    if (!out) {
        std::cerr << "Could not open output filename\n";
        exit(1);
    }

    out << contents.get_str(16);
}

void write_text(const std::string& filename, const std::string& contents) {
    std::ofstream out(filename);
    if (!out) {
        std::cerr << "Could not open output filename\n";
        exit(1);
    }

    out << contents;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <enc | dec> <input filename> <output filename> <key filename>\n";
        exit(1);
    }

    std::string command = argv[1];
    std::string input = argv[2];
    std::string output = argv[3];
    std::string keyfile = argv[4];

    RSA rsa;

    std::ifstream in(input);
    if (!in) {
        std::cerr << "Could not open message file\n";
        exit(1);
    }

    if (command == "enc") {
        PublicKey key = rsa.load_public_key(keyfile);

        std::stringstream buffer;
        buffer << in.rdbuf();
        std::string plaintext = buffer.str();

        mpz_class m = text_to_mpz(plaintext);

        mpz_class ciphertext = rsa.encrypt(m, key);
        
        write_mpz(output, ciphertext);
    } else if (command == "dec") {
        PrivateKey key = rsa.load_private_key(keyfile);

        std::stringstream buffer;
        buffer << in.rdbuf();
        std::string ciphertext = buffer.str();

        mpz_class ctext_mpz(ciphertext, 16);

        mpz_class plaintext_mpz = rsa.decrypt(ctext_mpz, key);

        std::string plaintext = mpz_to_text(plaintext_mpz);

        write_text(output, plaintext);
    } else {
        std::cerr << "Usage: " << argv[0] << " <enc | dec> <input filename> <output filename> <key filename>\n";
        exit(1);
    }
}