#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <time.h>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

int main (int argc, char* argv[]) {

    std::cerr << '\a' << std::flush;

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ciphertext directory>\n";
        exit(1);
    }

    const char* socket_path = "/tmp/rsa_oracle.sock";

    struct timespec start, end;
    
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(1);
    }

    fs::path directory(argv[1]);

    if (!fs::exists(directory)) {
        std::cerr << "Given path does not exist: " << directory << "\n";
        exit(1);
    }

    if (!fs::is_directory(directory)) {
        std::cerr << "Given path is not a directory: " << directory << "\n";
        exit(1);
    }

    std::vector<std::vector<uint64_t>> timing_results;

    std::vector<fs::path> files;

    for (const auto& file : fs::directory_iterator(directory)) {
        if (file.is_regular_file() && file.path().extension() == ".txt") {
            files.push_back(file.path());
        }
    }

    std::sort(files.begin(), files.end());

    for (const auto& file : files) {
        std::vector<uint64_t> times_for_sample;
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line)) {
            std::string msg = line + "\n";
            for (int i = 0; i < 1000; i++) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &start);
                ssize_t sent = write(fd, msg.c_str(), msg.size());
                if (sent < 0) {
                    perror("write");
                }

                std::string response;
                char ch;
                while (read(fd, &ch, 1) == 1) {
                    if (ch == '\n') break;
                    response.push_back(ch);
                }
                clock_gettime(CLOCK_MONOTONIC_RAW, &end);
                uint64_t elapsed_ns = (end.tv_sec - start.tv_sec) * 1'000'000'000ULL + (end.tv_nsec - start.tv_nsec);
                times_for_sample.push_back(elapsed_ns);
            }
        }
        timing_results.push_back(times_for_sample);
    }

    std::ofstream out("timing_results.csv");
    if (!out) {
        std::cerr << "Timing output file creation failed\n";
        exit(1);
    }
    out << "sample,iteration,time_ns\n";
    for (size_t i = 0; i < timing_results.size(); i++) {
        for (size_t j = 0; j < timing_results[i].size(); j++) {
            out << i << "," << j << "," << timing_results[i][j] << "\n";
        }
    }

    close(fd);

    std::cerr << '\a' << std::flush;
    return 0;
}