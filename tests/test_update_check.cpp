// Unit tests for the update check's version handling: parsing release tags, comparing versions, and
// when an automatic check is due.
#include "update_check.h"

#include <iostream>
#include <string>

using namespace update_check;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static bool parses_as(const std::string& text, uint32_t major, uint32_t minor, uint32_t patch) {
    auto v = parse_version(text);
    return v && v->major == major && v->minor == minor && v->patch == patch;
}

static bool newer(const std::string& a, const std::string& b) { return is_newer(*parse_version(a), *parse_version(b)); }

int main() {
    std::cout << "Parsing versions\n";
    CHECK(parses_as("1.2.0", 1, 2, 0), "1.2.0");
    CHECK(parses_as("v1.2.0", 1, 2, 0), "a leading v (release tags)");
    CHECK(parses_as("V3.10.7", 3, 10, 7), "a leading V");
    CHECK(parses_as("1.3", 1, 3, 0), "two parts: patch 0");
    CHECK(parses_as("0.0.1", 0, 0, 1), "zeros");
    CHECK(parses_as("999999.0.0", 999999, 0, 0), "six digits");
    for (const char* bad : {"", "v", "1", "v1", "1.", "1.2.", ".1.2", "1..2", "1.2.3.4", "1.2.0-rc1", "1.2.0 ",
                            " 1.2.0", "1.2.x", "vv1.2.0", "1,2,0", "1234567.0.0", "-1.2.0", "+1.2.0", "1.2.0\n",
                            "Lattice-PQ v1.2.0"})
        CHECK(!parse_version(bad), std::string("rejects \"") + bad + "\"");
    CHECK(to_string(*parse_version("v2.5")) == "2.5.0", "to_string writes all three parts");

    std::cout << "Comparing versions\n";
    CHECK(newer("1.3.0", "1.2.0"), "a later minor is newer");
    CHECK(newer("1.2.1", "1.2.0"), "a later patch is newer");
    CHECK(newer("2.0.0", "1.99.99"), "a later major beats any minor and patch");
    CHECK(newer("1.10.0", "1.9.0"), "numbers compare as numbers, not text");
    CHECK(!newer("1.2.0", "1.2.0"), "the same version is not newer");
    CHECK(!newer("1.2", "1.2.0"), "1.2 and 1.2.0 are the same");
    CHECK(!newer("1.1.9", "1.2.0"), "an older release is not newer");
    CHECK(!newer("0.9.0", "1.0.0"), "an older major is not newer");

    std::cout << "This build's version\n";
    CHECK(parse_version(current_version_string()).has_value(),
          std::string("the build's version parses (") + current_version_string() + ")");
    CHECK(to_string(current_version()) == current_version_string(), "current_version matches the build's version");

    std::cout << "When an automatic check is due\n";
    const int64_t now = 1'800'000'000;
    CHECK(check_due(0, now), "never checked: due");
    CHECK(!check_due(now - 60, now), "a minute ago: not due");
    CHECK(!check_due(now - CHECK_INTERVAL_SECONDS + 1, now), "just under a day ago: not due");
    CHECK(check_due(now - CHECK_INTERVAL_SECONDS, now), "a day ago: due");
    CHECK(check_due(now + 3600, now), "a last check in the future (clock moved back): due");
    CHECK(check_due(-5, now), "a nonsense negative time: due");

    std::cout << "Fixed addresses\n";
    CHECK(std::string(RELEASES_PAGE).rfind("https://github.com/", 0) == 0, "the releases page is on github.com over https");
    CHECK(std::string(LATEST_RELEASE_API).rfind("https://api.github.com/", 0) == 0, "the API is api.github.com over https");

    std::cout << (failures ? "FAILED: " + std::to_string(failures) : std::string("All passed")) << "\n";
    return failures ? 1 : 0;
}
