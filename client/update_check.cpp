#include "update_check.h"

#include <tuple>
#include <vector>

#ifndef PQ_APP_VERSION
#error "PQ_APP_VERSION must be defined by the build (CMakeLists.txt sets it from the project version)"
#endif

namespace update_check {

std::optional<Version> parse_version(const std::string& text) {
    size_t i = 0;
    if (i < text.size() && (text[i] == 'v' || text[i] == 'V')) i++;
    std::vector<uint32_t> parts;
    while (true) {
        // One number: 1 to 6 digits.
        size_t start = i;
        uint32_t value = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            if (i - start >= 6) return std::nullopt;
            value = value * 10 + static_cast<uint32_t>(text[i] - '0');
            i++;
        }
        if (i == start) return std::nullopt;
        parts.push_back(value);
        if (i == text.size()) break;
        if (text[i] != '.' || parts.size() == 3) return std::nullopt;
        i++;
    }
    if (parts.size() < 2) return std::nullopt;
    Version v;
    v.major = parts[0];
    v.minor = parts[1];
    v.patch = parts.size() == 3 ? parts[2] : 0;
    return v;
}

bool is_newer(const Version& candidate, const Version& current) {
    return std::tie(candidate.major, candidate.minor, candidate.patch) > std::tie(current.major, current.minor, current.patch);
}

std::string to_string(const Version& v) {
    return std::to_string(v.major) + "." + std::to_string(v.minor) + "." + std::to_string(v.patch);
}

const char* current_version_string() { return PQ_APP_VERSION; }

Version current_version() {
    // The build's own version always parses (the tests check it); fall back to 0.0.0 rather than fail.
    return parse_version(PQ_APP_VERSION).value_or(Version{});
}

bool check_due(int64_t last_check, int64_t now) {
    if (last_check <= 0 || last_check > now) return true;
    return now - last_check >= CHECK_INTERVAL_SECONDS;
}

}  // namespace update_check
