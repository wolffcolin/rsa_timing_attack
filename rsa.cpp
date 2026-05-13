#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <string>
#include <cerrno>
#include <stdexcept>
#include <unistd.h>
#include <cctype>
#include "rsa.h"

bool is_hex_string(const std::string& s) {
    if (s.empty()) return false;

    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

PublicKey RSA::load_public_key(const std::string& keyfile) {
    struct PublicKey pub_k;

    std::ifstream in(keyfile);
    if (!in) {
        std::cerr << "Could not open public key file\n";
        exit(1);
    }

    std::string line;
    int ctr = 0;
    while(std::getline(in, line)) {
        if (ctr == 0) {
            if (line != "type=public") {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
            ctr++;
            continue;
        }

        if (ctr == 1) {
            if (line != "format=rsa") {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
            ctr++;
            continue;
        }

        if (ctr == 2) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "n") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class n(value_str, 16);
                pub_k.n = n;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr == 3) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "e") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class e(value_str, 16);
                pub_k.e = e;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr > 3) {
            std::cerr << "Key file format is not valid\n";
            exit(1);
        }

        ctr++;
    }

    if (ctr != 4) {
        std::cerr << "Key file format is not valid\n";
        exit(1);
    }

    return pub_k;
}

PrivateKey RSA::load_private_key(const std::string& keyfile) {
    struct PrivateKey pri_k;

    std::ifstream in(keyfile);
    if (!in) {
        std::cerr << "Could not open private key file\n";
        exit(1);
    }

    std::string line;
    int ctr = 0;
    while (std::getline(in, line)) {
        if (ctr == 0) {
            if (line != "type=private") {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
            ctr++;
            continue;
        }

        if (ctr == 1) {
            if (line != "format=rsa") {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
            ctr++;
            continue;
        }

        if (ctr == 2) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "n") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class n(value_str, 16);
                pri_k.n = n;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr == 3) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "d") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class d(value_str, 16);
                pri_k.d = d;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr == 4) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "p") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class p(value_str, 16);
                pri_k.p = p;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr == 5) {
            size_t equals_pos = line.find('=');
            if (equals_pos == std::string::npos) {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }

            std::string name = line.substr(0, equals_pos);
            std::string value_str = line.substr(equals_pos + 1);

            if (name == "q") {
                if (!is_hex_string(value_str)) {
                    std::cerr << "Key file format is not valid\n";
                    exit(1);
                }

                mpz_class q(value_str, 16);
                pri_k.q = q;
            } else {
                std::cerr << "Key file format is not valid\n";
                exit(1);
            }
        }

        if (ctr > 5) {
            std::cerr << "Key file format is not valid\n";
            exit(1);
        }

        ctr++;
    }

    if (ctr != 6) {
        std::cerr << "Key file format is not valid\n";
        exit(1);
    }

    return pri_k;
}

mpz_class RSA::encrypt(const mpz_class& m, const PublicKey& key) {
    if (key.e <= 0 || key.n <= 0) {
        std::cerr << "Error: key value(s) not positive\n";
        exit(1);
    }

    if (m < 0 || m >= key.n) {
        std::cerr << "Error: m size does not fit range 0 <= M < n\n";
        exit(1);
    }

    mpz_class c;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), key.e.get_mpz_t(), key.n.get_mpz_t());

    return c;
}

mpz_class RSA::decrypt(const mpz_class& c, const PrivateKey&  key) {
    if (key.d <= 0 || key.n <= 0) {
        std::cerr << "Error: key value(s) not positive\n";
        exit(1);
    }

    if (c < 0 || c >= key.n) {
        std::cerr << "Error: m size does not fit range 0 <= C < n\n";
        exit(1);
    }

    // mpz powm is too optimized compared to square and multiply from class
    //mpz_class m;
    //mpz_powm(m.get_mpz_t(), c.get_mpz_t(), key.d.get_mpz_t(), key.n.get_mpz_t());

    mpz_class result = 1;
    mpz_class base = c % key.n;
    mp_bitcnt_t bits = mpz_sizeinbase(key.d.get_mpz_t(), 2);

    for (mp_bitcnt_t i = bits; i > 0; i--) {
        result = (result * result) % key.n;
        if (mpz_tstbit(key.d.get_mpz_t(), i - 1)) {
            result = (result * base) % key.n;
        }
    }

    return result;
}