#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>
#include <cerrno>
#include <gmpxx.h>
#include <cctype>
#include "rsa.h"

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <key filename>";
        return 1;
    }

    std::string keyfile = argv[1];

    RSA rsa;

    PrivateKey key = rsa.load_private_key(keyfile);

    const char* path = "/tmp/rsa_oracle.sock";

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket creation failed");
        return 1;
    }

    // fill address
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    // remove old socket file
    unlink(path);
    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("socket bind failed");
        close(server_fd);
        return 1;
    }

    //listen
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        unlink(path);
        return 1;
    }

    while (true) {
        // accept
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        std::string request;
        size_t char_count = 0;
        while (true) {
            char ch;
            ssize_t n = read(client_fd, &ch, 1);
            char_count++;

            if (n == 0) break; // client closed
            if (n < 0) break; // client error

            if (ch == '\n') {
                if (!request.empty() && request.back() == '\r') {
                    request.pop_back();
                }
                // request is full, process decrypt op, send response
                // empty out request string for next request

                if (!is_hex_string(request)) {
                    std::string err = "ERROR\n";
                    write(client_fd, err.c_str(), err.size());
                } else {
                    mpz_class cipherhex(request, 16);
                    mpz_class plainhex = rsa.decrypt(cipherhex, key);
                    std::string response = plainhex.get_str(16) + "\n";
                    write(client_fd, response.c_str(), response.size());
                }

                request.clear();
                char_count = 0;
                continue;
            }
            if (request.size() >= 512) continue;
            request.push_back(ch);
        }

        // write
        //if (n > 0) {
            //write(client_fd, request.c_str(), request.size());
        //}

        close(client_fd);
    }

    return 0;
}