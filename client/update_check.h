#pragma once

// Checking for a newer release (no Qt, so it can be tested on its own). The app only compares version
// numbers and points the user at the releases page: it never downloads or installs anything.

#include <cstdint>
#include <optional>
#include <string>

namespace update_check {

// Where releases are published. The page the app opens is fixed here, never taken from a server's reply.
inline constexpr const char* RELEASES_PAGE = "https://github.com/sova-nova/lattice-pq/releases/latest";
inline constexpr const char* LATEST_RELEASE_API = "https://api.github.com/repos/sova-nova/lattice-pq/releases/latest";

// At most one automatic check a day.
constexpr int64_t CHECK_INTERVAL_SECONDS = 24 * 60 * 60;

struct Version {
    uint32_t major = 0, minor = 0, patch = 0;
};

// "1.2.0", "v1.2.0" or "1.2" (patch 0). Anything else (a suffix such as "-rc1", spaces, a missing or
// overlong number) is rejected: a pre-release is never offered as an update.
std::optional<Version> parse_version(const std::string& text);

// True if `candidate` is a later version than `current`.
bool is_newer(const Version& candidate, const Version& current);

std::string to_string(const Version& v);

// This build's version, from the CMake project version.
const char* current_version_string();
Version current_version();

// Whether an automatic check is due, given when the last one was made (seconds since the epoch; 0 for
// never). A last check in the future (the clock was moved back) counts as due, so it can't block checks.
bool check_due(int64_t last_check, int64_t now);

}  // namespace update_check
