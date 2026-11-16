#pragma once

// Ports for the relays the integration tests start (Linux and macOS only, like those tests).
//
// A relay's port is chosen once and kept for its life, since some tests restart a relay and expect it back where it was.
// It must not come from the range the OS hands out for outgoing connections (Linux: 32768-60999; macOS: 49152-65535):
// the tests' own connections take ports from there all the time, and a relay that tries to listen on one of them while
// it is taken can't start ("could not start the ... relay", seen now and then before this existed). So ports are picked
// below 32768, at random (parallel test runs rarely meet), and each is checked to be free when picked.

#include <cstdint>
#include <ctime>
#include <random>
#include <set>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

inline int free_test_port() {
    static std::set<int> handed_out;
    static std::mt19937 rng(static_cast<uint32_t>(getpid()) * 2654435761u ^ static_cast<uint32_t>(std::time(nullptr)));
    for (int tries = 0; tries < 2000; tries++) {
        const int port = 20000 + static_cast<int>(rng() % 12000);  // 20000-31999
        if (handed_out.count(port)) continue;
        const int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));  // as the relay does, so a port in TIME_WAIT still counts as free
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<uint16_t>(port));
        const bool free = bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
        close(s);
        if (free) {
            handed_out.insert(port);
            return port;
        }
    }
    return 20000 + static_cast<int>(getpid() % 12000);  // nothing free found: fall back as before
}
