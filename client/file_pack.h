#pragma once

// Packing many files, or a folder, into one file so they can be sent as one (bulk transfers). A pack is a plain,
// uncompressed tar archive (ustar, with a pax "path" record for long or non-ASCII paths), so anyone without Lattice
// can still open it with any archive tool. Everything in it sits under one top folder ("Photos/..."), and the file
// is sent named "<top folder>.lattice.tar".
//
// The archive comes from someone else, so unpacking is strict. It accepts only what this module's own writer
// produces: every header is rebuilt with the writer's code and must match byte for byte (so a wrong checksum, an
// owner, odd permissions, a link, a device or an extra pax record are all refused without a rule for each).
// Paths must be relative, under the one top folder, made of names that are already safe to save
// (attachment::sanitize_filename leaves them unchanged), with every folder listed before what it holds, and no two
// paths that differ only in letter case. The whole archive is checked before anything is written, and it is
// unpacked into a hidden folder that is renamed into place only once everything succeeded.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace file_pack {

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

// How a pack's file name ends, so a receiving Lattice knows to offer unpacking it.
inline constexpr const char* NAME_SUFFIX = ".lattice.tar";

constexpr uint64_t MAX_PACK_BYTES = 5ull * 1024 * 1024 * 1024;  // the whole archive
constexpr size_t MAX_ENTRIES = 10000;                           // files and folders, not counting the top folder
                                                                // (file_pack.cpp's messages say "10,000": keep in step)
constexpr size_t MAX_DEPTH = 32;                                // names in a path, the top folder included
constexpr size_t MAX_PATH_BYTES = 1024;

// Reports progress; returning false cancels.
using Progress = std::function<bool(uint64_t done, uint64_t total)>;

// --- Sending ---

struct Item {
    std::string path;  // in the archive: "Top/sub/name", '/'-separated UTF-8, no trailing slash
    bool dir = false;
    uint64_t size = 0;    // files only
    int64_t mtime = 0;    // seconds since the epoch
    fs::path source;      // where to read it from (files only)
};

struct Plan {
    std::string root;           // the top folder's name (safe to use as a file name)
    std::vector<Item> items;    // the top folder first, every folder before what it holds
    size_t files = 0, folders = 0;  // not counting the top folder
    uint64_t content_bytes = 0;     // the files' sizes added up
    uint64_t archive_bytes = 0;     // the size of the archive write() makes
    std::vector<fs::path> skipped;  // links and special files, left out (never followed)

    std::string file_name() const { return root + NAME_SUFFIX; }
};

// A folder and everything in it; the folder's name becomes the top folder.
std::optional<Plan> plan_folder(const fs::path& folder, std::string& error);
// Files and folders chosen together, each placed in a top folder called `root_name` (made safe first).
std::optional<Plan> plan_items(const std::string& root_name, const std::vector<fs::path>& sources, std::string& error);

// Writes the archive to `out` (replacing it). Fails if a file can't be read or changed size since it was planned,
// if there isn't room for it, or if `progress` cancels; nothing is left behind then.
bool write(const Plan& plan, const fs::path& out, const Progress& progress, std::string& error);

// --- Receiving ---

bool is_pack_name(const std::string& file_name);

struct Unpacked {
    fs::path saved;  // the folder it was unpacked into (the top folder's name, or "name (2)"... if that is taken)
    size_t files = 0, folders = 0;
    uint64_t content_bytes = 0;
};

// Checks the whole archive, then unpacks it into a new folder in `directory`. Fails, leaving nothing behind, if
// the archive breaks any rule, there isn't room, or `progress` cancels.
std::optional<Unpacked> unpack(const fs::path& archive, const fs::path& directory, const Progress& progress, std::string& error);

struct Entry {
    std::string path;  // as in Item
    bool dir = false;
    uint64_t size = 0;
    int64_t mtime = 0;
};
// Reads and checks an archive of `total` bytes from `in` (seekable) without writing anything. Used by unpack()
// and by the fuzzer.
bool scan(std::istream& in, uint64_t total, std::vector<Entry>& entries, std::string& error);

namespace detail {
// The bytes write() puts before an entry's data: a pax header and its record when needed, then the ustar header.
Bytes entry_header(const std::string& path, bool dir, uint64_t size, int64_t mtime);
uint64_t padding(uint64_t size);  // zero bytes after `size` bytes of data, up to the next 512-byte block
Bytes end_of_archive();           // two zero blocks
// A path as a pack may hold it (ignoring the limits on depth and length).
bool valid_path(const std::string& path);
}  // namespace detail

}  // namespace file_pack
