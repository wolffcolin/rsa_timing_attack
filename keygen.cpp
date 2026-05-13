#include <iostream>
#include <gmpxx.h>
#include <fstream>
#include <string>
#include <sys/random.h>
#include <array>
#include <cerrno>
#include <stdexcept>
#include <unistd.h>

class KeyGenerator {
private:
    mpz_class e;
    mpz_class d;
    mpz_class n;
    mpz_class phi;
    mpz_class p_final;
    mpz_class q_final;
    int target_prime_size;

    gmp_randclass rng;

    // get 256 bits of random from OS
    mpz_class get_random_256bit() {
        uint8_t buf[32];
        size_t total = 0;

        while (total < sizeof(buf)) {
            ssize_t n = getrandom(buf + total, sizeof(buf) - total, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("getrandom failed");
            }
            total += static_cast<size_t>(n);
        }
        
        mpz_class x;
        mpz_import(x.get_mpz_t(), 32, 1, 1, 1, 0, buf);

        return x;
    }

    // generate n bit prime
    mpz_class generate_prime(int n) {
        mpz_class x;
        x = rng.get_z_bits(n); // get random bits

        mpz_setbit(x.get_mpz_t(), n-1); // force top bit 1
        mpz_setbit(x.get_mpz_t(), 0); // force bottom bit 1
        
        while (mpz_probab_prime_p(x.get_mpz_t(), 25) <= 0) {
            x = rng.get_z_bits(n); // get random bits
            mpz_setbit(x.get_mpz_t(), n-1); // force top bit 1
            mpz_setbit(x.get_mpz_t(), 0); // force bottom bit 1
        }

        return x;
    }

    bool are_coprime(const mpz_class& a, const mpz_class&b) {
        mpz_class g;
        mpz_gcd(g.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
        return g == 1;
    }

public:
    KeyGenerator(int tm_size, mpz_class exp) : rng(gmp_randinit_default) {
        target_prime_size = tm_size / 2;
        e = exp;

        mpz_class seed = get_random_256bit(); // seed value
        rng.seed(seed);
    }


    void generate_keys() {
        mpz_class p, q, n_candidate, phi_candidate;

        do {
            p = generate_prime(target_prime_size);

            do {
                q = generate_prime(target_prime_size);
            } while (q == p);

            n_candidate = p * q;
            phi_candidate = (p - 1) * (q - 1);
        } while (mpz_sizeinbase(n_candidate.get_mpz_t(), 2) != static_cast<size_t>(target_prime_size * 2) || !are_coprime(e, phi_candidate));

        n = n_candidate;
        phi = phi_candidate;
        p_final = p;
        q_final = q;

        if (!mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t())) {
            std::cerr << "key generation failed\n";
            exit(1);
        }
    }

    const mpz_class& get_e() {
        return e;
    }

    const mpz_class& get_d() {
        return d;
    }

    const mpz_class& get_n() {
        return n;
    }

    const mpz_class& get_phi() {
        return phi;
    }
    
    const mpz_class& get_p() {
        return p_final;
    }

    const mpz_class& get_q() {
        return q_final;
    }
};

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

bool is_numeric(const std::string& s) {
    if (s.empty()) return false;

    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return true;
}

int main (int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <public key output filename> <private key output filename> [target modulus size (default 2048 bits)]";
        exit(1);
    }

    std::string public_output_filename = argv[1];
    std::string private_output_filename = argv[2];

    std::ofstream pub_out(public_output_filename);
    if (!pub_out) {
        std::cerr << "Failed to open output file for public key\n";
        exit(1);
    }

    std::ofstream pri_out(private_output_filename);
    if (!pri_out) {
        std::cerr << "Failed to open output file for private key\n";
        exit(1);
    }

    int target_modulus_size;

    if (argc >= 4) {
        if (!is_numeric(argv[3])) {
            std::cerr << "Target modulus size must be numeric\n";
            exit(1);
        }
        target_modulus_size = std::stoi(argv[3]);
        if (target_modulus_size % 2 != 0 || target_modulus_size < 512) {
            std::cerr << "Target modulus size must be an even number that is at least 512\n";
            exit(1);
        }

    } else {
        target_modulus_size = 2048;
    }

    mpz_class e = 65537;

    KeyGenerator keygen(target_modulus_size, e);

    keygen.generate_keys();

    struct PublicKey pub_key;
    struct PrivateKey pri_key;

    pub_key.n = keygen.get_n();
    pub_key.e = keygen.get_e();

    pri_key.n = keygen.get_n();
    pri_key.d = keygen.get_d();
    pri_key.p = keygen.get_p();
    pri_key.q = keygen.get_q();

    pub_out << "type=public\n" << "format=rsa\n" << "n=";
    pub_out << pub_key.n.get_str(16) << "\n"; // output n as hexadecimal
    pub_out << "e=";
    pub_out << pub_key.e.get_str(16);

    pri_out << "type=private\n" << "format=rsa\n" << "n=";
    pri_out << pri_key.n.get_str(16) << "\n";
    pri_out << "d=";
    pri_out << pri_key.d.get_str(16) << "\n";
    pri_out << "p=";
    pri_out << pri_key.p.get_str(16) << "\n";
    pri_out << "q=";
    pri_out << pri_key.q.get_str(16) << "\n";

    
    pri_out.close();
    pub_out.close();

    return 0;
}