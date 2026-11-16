#include "file_pack.h"

#include "attachment.h"  // sanitize_filename, unique_path
#include "scope_exit.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <istream>
#include <set>

namespace file_pack {

namespace {

constexpr size_t BLOCK = 512;
constexpr int64_t MAX_MTIME = 077777777777;          // 11 octal digits
constexpr uint64_t MAX_OCTAL_SIZE = 077777777777ull;  // ustar's size field: just under 8 GiB, above MAX_PACK_BYTES
constexpr size_t MAX_PAX_BYTES = 4096;                 // one "path" record for a path of at most MAX_PATH_BYTES
constexpr size_t COPY_BYTES = 1024 * 1024;
static_assert(MAX_PACK_BYTES <= MAX_OCTAL_SIZE, "a file in a pack must fit ustar's size field");

using Block = std::array<uint8_t, BLOCK>;

std::string size_text(uint64_t bytes) {
    const double gib = 1024.0 * 1024 * 1024, mib = 1024.0 * 1024;
    char buf[32];
    if (bytes >= static_cast<uint64_t>(gib)) std::snprintf(buf, sizeof(buf), "%.1f GiB", static_cast<double>(bytes) / gib);
    else std::snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(bytes) / mib);
    return buf;
}

int64_t clamp_mtime(int64_t t) { return std::min<int64_t>(std::max<int64_t>(t, 0), MAX_MTIME); }

// Converting between the file system's clock and Unix time (C++17 has no direct conversion).
int64_t to_unix(fs::file_time_type t) {
    using namespace std::chrono;
    const auto sys = system_clock::now() + duration_cast<system_clock::duration>(t - fs::file_time_type::clock::now());
    return duration_cast<seconds>(sys.time_since_epoch()).count();
}

fs::file_time_type from_unix(int64_t seconds_since_epoch) {
    using namespace std::chrono;
    const auto sys = system_clock::time_point(duration_cast<system_clock::duration>(seconds(seconds_since_epoch)));
    return fs::file_time_type::clock::now() + duration_cast<fs::file_time_type::duration>(sys - system_clock::now());
}

int64_t mtime_of(const fs::path& p) {
    std::error_code ec;
    const auto t = fs::last_write_time(p, ec);
    return ec ? 0 : clamp_mtime(to_unix(t));
}

// `width - 1` octal digits, zero padded, then a NUL.
void put_octal(uint8_t* field, size_t width, uint64_t value) {
    for (size_t i = width - 1; i-- > 0;) {
        field[i] = static_cast<uint8_t>('0' + (value & 7));
        value >>= 3;
    }
    field[width - 1] = 0;
}

// The reverse, strictly: exactly `width - 1` octal digits and a NUL.
std::optional<uint64_t> get_octal(const uint8_t* field, size_t width) {
    uint64_t v = 0;
    for (size_t i = 0; i + 1 < width; i++) {
        if (field[i] < '0' || field[i] > '7') return std::nullopt;
        v = (v << 3) | static_cast<uint64_t>(field[i] - '0');
    }
    if (field[width - 1] != 0) return std::nullopt;
    return v;
}

Block ustar_block(const std::string& name, char type, uint64_t size, int64_t mtime) {
    Block b{};
    std::memcpy(b.data(), name.data(), std::min<size_t>(100, name.size()));
    put_octal(b.data() + 100, 8, type == '5' ? 0755 : 0644);  // mode
    put_octal(b.data() + 108, 8, 0);                          // owner
    put_octal(b.data() + 116, 8, 0);                          // group
    put_octal(b.data() + 124, 12, size);
    put_octal(b.data() + 136, 12, static_cast<uint64_t>(mtime));
    b[156] = static_cast<uint8_t>(type);
    std::memcpy(b.data() + 257, "ustar", 6);  // with its NUL
    b[263] = '0';
    b[264] = '0';
    std::memset(b.data() + 148, ' ', 8);  // the checksum counts its own field as spaces
    unsigned sum = 0;
    for (uint8_t c : b) sum += c;
    put_octal(b.data() + 148, 7, sum);  // six digits and a NUL...
    b[155] = ' ';                       // ...then a space, as tar writes it
    return b;
}

// "<length> key=value\n", where the length counts the whole record, its own digits included.
std::string pax_record(const std::string& key, const std::string& value) {
    const std::string body = " " + key + "=" + value + "\n";
    size_t len = body.size() + 1;
    while (std::to_string(len).size() + body.size() != len) len = std::to_string(len).size() + body.size();
    return std::to_string(len) + body;
}

bool plain_ascii(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
}

std::string lower_ascii(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

size_t depth_of(const std::string& path) { return static_cast<size_t>(std::count(path.begin(), path.end(), '/')) + 1; }

// One name in a path. Safe as attachment::sanitize_filename defines it, except that one leading dot is allowed, so
// a folder's hidden files (".gitignore") keep their names.
bool valid_component(const std::string& c) {
    if (c.empty() || c == "." || c == "..") return false;
    const std::string rest = c[0] == '.' ? c.substr(1) : c;
    if (rest.empty() || rest[0] == '.') return false;
    if (c.size() > 200) return false;
    return attachment::sanitize_filename(rest) == rest;
}

// A name from this computer, made into one valid_component accepts.
std::string safe_component(const std::string& raw) {
    size_t dots = 0;
    while (dots < raw.size() && raw[dots] == '.') dots++;
    std::string s = raw.substr(dots);
    // sanitize_filename can leave something it would change again (cutting a long name can expose a trailing dot).
    for (int i = 0; i < 4; i++) {
        const std::string next = attachment::sanitize_filename(s);
        if (next == s) break;
        s = next;
    }
    if (dots > 0 && s.size() < 200) s = "." + s;
    return valid_component(s) ? s : std::string("file");
}

// `name`, or "stem (2).ext", "stem (3).ext"... if a name differing only in letter case is already used here.
std::string unique_in(const std::string& name, std::set<std::string>& used) {
    std::string candidate = name;
    std::string stem = name, ext;
    const size_t dot = name.rfind('.');
    if (dot != std::string::npos && dot > 0) {
        stem = name.substr(0, dot);
        ext = name.substr(dot);
    }
    for (int n = 2; used.count(lower_ascii(candidate)) && n < 100000; n++) candidate = safe_component(stem + " (" + std::to_string(n) + ")" + ext);
    used.insert(lower_ascii(candidate));
    return candidate;
}

// Collects a Plan, checking the limits as it goes.
class Planner {
public:
    explicit Planner(std::string& error) : error_(error) {}
    Plan plan;

    bool start(const std::string& root, int64_t mtime) {
        plan.root = root;
        return add(Item{root, true, 0, mtime, {}});
    }

    // A file or folder named `name` (already safe and unique) inside the folder at `parent`.
    bool add_source(const fs::path& source, const std::string& parent, const std::string& name, bool follow) {
        std::error_code ec;
        const fs::file_status st = follow ? fs::status(source, ec) : fs::symlink_status(source, ec);
        if (ec) return fail("Couldn't read " + source.u8string() + ": " + ec.message());
        const std::string path = parent + "/" + name;
        if (fs::is_directory(st)) {
            if (!add(Item{path, true, 0, mtime_of(source), {}})) return false;
            return walk(source, path);
        }
        if (fs::is_regular_file(st)) {
            const uint64_t size = fs::file_size(source, ec);
            if (ec) return fail("Couldn't read " + source.u8string() + ": " + ec.message());
            return add(Item{path, false, size, mtime_of(source), source});
        }
        plan.skipped.push_back(source);  // a link (never followed inside a folder), a device, a socket...
        return true;
    }

    bool finish() {
        plan.archive_bytes += BLOCK * 2;
        if (plan.archive_bytes > MAX_PACK_BYTES)
            return fail("That's " + size_text(plan.archive_bytes) + " in all; files sent together can be at most " + size_text(MAX_PACK_BYTES) + ".");
        return true;
    }

private:
    std::string& error_;

    bool fail(const std::string& e) {
        error_ = e;
        return false;
    }

    bool add(Item item) {
        if (plan.items.size() > MAX_ENTRIES) return fail("That's more than 10,000 files and folders; send them in smaller groups.");
        if (depth_of(item.path) > MAX_DEPTH) return fail("Folders are nested too deeply (more than " + std::to_string(MAX_DEPTH) + " levels): " + item.path);
        if (item.path.size() + (item.dir ? 1 : 0) > MAX_PATH_BYTES) return fail("A path is too long to send: " + item.path);
        plan.archive_bytes += detail::entry_header(item.path, item.dir, item.size, item.mtime).size() + item.size + detail::padding(item.size);
        // Stop early rather than walk a huge folder to the end.
        if (plan.archive_bytes > MAX_PACK_BYTES)
            return fail("That's more than " + size_text(MAX_PACK_BYTES) + "; files sent together can be at most that.");
        if (plan.items.size() > 0) (item.dir ? plan.folders : plan.files)++;
        plan.content_bytes += item.size;
        plan.items.push_back(std::move(item));
        return true;
    }

    bool walk(const fs::path& dir, const std::string& path) {
        std::error_code ec;
        std::vector<fs::path> children;
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) children.push_back(it->path());
        if (ec) return fail("Couldn't read the folder " + dir.u8string() + ": " + ec.message());
        std::sort(children.begin(), children.end(), [](const fs::path& a, const fs::path& b) { return a.filename().u8string() < b.filename().u8string(); });
        std::set<std::string> used;
        for (const auto& child : children)
            if (!add_source(child, path, unique_in(safe_component(child.filename().u8string()), used), false)) return false;
        return true;
    }
};

// Reads exactly what it is told to, never past `total`.
class Reader {
public:
    Reader(std::istream& in, uint64_t total) : in_(in), total_(total) {}
    bool read(uint8_t* p, uint64_t n) {
        if (n > total_ - pos_) return false;
        in_.read(reinterpret_cast<char*>(p), static_cast<std::streamsize>(n));
        if (in_.gcount() != static_cast<std::streamsize>(n)) return false;
        pos_ += n;
        return true;
    }
    bool skip(uint64_t n) {
        if (n > total_ - pos_) return false;
        in_.seekg(static_cast<std::streamoff>(n), std::ios::cur);
        if (!in_) return false;
        pos_ += n;
        return true;
    }
    bool at_end() const { return pos_ == total_; }

private:
    std::istream& in_;
    uint64_t total_, pos_ = 0;
};

// Called for each entry once its header has been checked; must consume exactly `entry.size` bytes of data.
using Visitor = std::function<bool(const Entry& entry, Reader& reader, std::string& error)>;

bool scan_impl(std::istream& in, uint64_t total, std::vector<Entry>& entries, std::string& error, const Visitor& visit) {
    entries.clear();
    if (total > MAX_PACK_BYTES) {
        error = "it is larger than " + size_text(MAX_PACK_BYTES);
        return false;
    }
    Reader r(in, total);
    auto fail = [&](const std::string& e) {
        error = e;
        return false;
    };
    std::set<std::string> folders, lower_paths;
    std::string root;
    while (true) {
        Block b;
        if (!r.read(b.data(), BLOCK)) return fail("it ends too early");
        const bool zero = std::all_of(b.begin(), b.end(), [](uint8_t c) { return c == 0; });
        if (zero) {
            if (!r.read(b.data(), BLOCK) || !std::all_of(b.begin(), b.end(), [](uint8_t c) { return c == 0; }))
                return fail("its end is malformed");
            if (!r.at_end()) return fail("there is data after its end");
            break;
        }
        Bytes consumed(b.begin(), b.end());  // every header byte, to compare with how the writer would lay it out
        std::string name;
        Block h = b;
        if (b[156] == 'x') {
            const auto n = get_octal(b.data() + 124, 12);
            if (!n || *n == 0 || *n > MAX_PAX_BYTES) return fail("it has a malformed extended header");
            std::string record(static_cast<size_t>(*n), '\0');
            Bytes pad(static_cast<size_t>(detail::padding(*n)));
            if (!r.read(reinterpret_cast<uint8_t*>(&record[0]), *n) || !r.read(pad.data(), pad.size())) return fail("it ends too early");
            consumed.insert(consumed.end(), record.begin(), record.end());
            consumed.insert(consumed.end(), pad.begin(), pad.end());
            const size_t space = record.find(' ');
            const std::string prefix = space == std::string::npos ? std::string() : record.substr(space + 1, 5);
            if (space == std::string::npos || prefix != "path=" || record.back() != '\n' || record.substr(0, space) != std::to_string(record.size()))
                return fail("it has an extended header Lattice doesn't write");
            name = record.substr(space + 6, record.size() - space - 7);
            if (!r.read(h.data(), BLOCK)) return fail("it ends too early");
            consumed.insert(consumed.end(), h.begin(), h.end());
        } else {
            name.assign(reinterpret_cast<const char*>(h.data()), strnlen(reinterpret_cast<const char*>(h.data()), 100));
        }
        const char type = static_cast<char>(h[156]);
        if (type != '0' && type != '5') return fail("it holds something other than files and folders (a link, for example)");
        const bool dir = type == '5';
        if (dir != (!name.empty() && name.back() == '/')) return fail("an entry's name doesn't match its type");
        if (dir) name.pop_back();
        const auto size = get_octal(h.data() + 124, 12);
        const auto mtime = get_octal(h.data() + 136, 12);
        if (!size || !mtime || (dir && *size != 0)) return fail("an entry has a malformed header");
        if (detail::entry_header(name, dir, *size, static_cast<int64_t>(*mtime)) != consumed)
            return fail("it isn't laid out the way Lattice writes packs");
        // The name isn't quoted: it is someone else's text, and could be made to mislead (text-direction characters).
        if (!detail::valid_path(name)) return fail("it holds a name that isn't safe to save");
        if (depth_of(name) > MAX_DEPTH || name.size() + (dir ? 1 : 0) > MAX_PATH_BYTES) return fail("a path in it is too deep or too long");
        if (root.empty()) {
            if (!dir || depth_of(name) != 1) return fail("it doesn't start with its top folder");
            root = name;
        } else {
            const size_t slash = name.rfind('/');
            if (slash == std::string::npos || name.compare(0, root.size() + 1, root + "/") != 0) return fail("it has more than one top folder");
            if (!folders.count(name.substr(0, slash))) return fail("an entry comes before the folder it's in");
        }
        if (!lower_paths.insert(lower_ascii(name)).second) return fail("it holds the same name twice (perhaps differing only in letter case)");
        if (entries.size() > MAX_ENTRIES) return fail("it holds more than 10,000 files and folders");
        if (dir) folders.insert(name);
        entries.push_back(Entry{name, dir, *size, static_cast<int64_t>(*mtime)});
        if (!visit(entries.back(), r, error)) return false;
        Bytes pad(static_cast<size_t>(detail::padding(*size)));
        if (!r.read(pad.data(), pad.size())) return fail("it ends too early");
        if (!std::all_of(pad.begin(), pad.end(), [](uint8_t c) { return c == 0; })) return fail("it has data where there should be none");
    }
    if (root.empty()) return fail("it is empty");
    return true;
}

}  // namespace

namespace detail {

uint64_t padding(uint64_t size) { return (BLOCK - size % BLOCK) % BLOCK; }

Bytes end_of_archive() { return Bytes(BLOCK * 2, 0); }

Bytes entry_header(const std::string& path, bool dir, uint64_t size, int64_t mtime) {
    mtime = clamp_mtime(mtime);
    const std::string name = dir ? path + "/" : path;
    Bytes out;
    std::string ustar_name = name;
    if (name.size() > 100 || !plain_ascii(name)) {
        // pax: the real path in a record; the ustar name is only for tools that don't read pax.
        const std::string record = pax_record("path", name);
        const Block x = ustar_block("PaxHeader", 'x', record.size(), 0);
        out.insert(out.end(), x.begin(), x.end());
        out.insert(out.end(), record.begin(), record.end());
        out.insert(out.end(), static_cast<size_t>(padding(record.size())), 0);
        ustar_name.clear();
        for (char c : name) ustar_name += static_cast<unsigned char>(c) < 0x80 ? c : '_';
        if (ustar_name.size() > 100) ustar_name.resize(100);
    }
    const Block h = ustar_block(ustar_name, dir ? '5' : '0', dir ? 0 : size, mtime);
    out.insert(out.end(), h.begin(), h.end());
    return out;
}

bool valid_path(const std::string& path) {
    if (path.empty()) return false;
    size_t start = 0;
    while (true) {
        const size_t slash = path.find('/', start);
        if (!valid_component(path.substr(start, slash == std::string::npos ? std::string::npos : slash - start))) return false;
        if (slash == std::string::npos) return true;
        start = slash + 1;
    }
}

}  // namespace detail

std::optional<Plan> plan_folder(const fs::path& folder, std::string& error) {
    fs::path p = folder;
    if (!p.has_filename()) p = p.parent_path();
    std::error_code ec;
    if (!fs::is_directory(p, ec)) {
        error = "That isn't a folder: " + folder.u8string();
        return std::nullopt;
    }
    Planner planner(error);
    if (!planner.start(safe_component(p.filename().u8string()), mtime_of(p))) return std::nullopt;
    // The folder itself is the top folder: walk what's in it.
    std::vector<fs::path> children;
    for (fs::directory_iterator it(p, ec), end; !ec && it != end; it.increment(ec)) children.push_back(it->path());
    if (ec) {
        error = "Couldn't read the folder " + p.u8string() + ": " + ec.message();
        return std::nullopt;
    }
    std::sort(children.begin(), children.end(), [](const fs::path& a, const fs::path& b) { return a.filename().u8string() < b.filename().u8string(); });
    std::set<std::string> used;
    for (const auto& child : children)
        if (!planner.add_source(child, planner.plan.root, unique_in(safe_component(child.filename().u8string()), used), false)) return std::nullopt;
    if (!planner.finish()) return std::nullopt;
    return std::move(planner.plan);
}

std::optional<Plan> plan_items(const std::string& root_name, const std::vector<fs::path>& sources, std::string& error) {
    if (sources.empty()) {
        error = "Nothing was chosen to send.";
        return std::nullopt;
    }
    // The same thing chosen twice is sent once; the rest in name order, so a pack's layout doesn't depend on the order
    // things were picked in.
    std::vector<fs::path> chosen;
    std::set<fs::path> seen;
    for (const auto& s : sources) {
        std::error_code ec;
        const fs::path key = fs::weakly_canonical(s, ec);
        if (seen.insert(ec ? s : key).second) chosen.push_back(s);
    }
    // Stable: of two things with the same name, the one picked first keeps it.
    std::stable_sort(chosen.begin(), chosen.end(), [](const fs::path& a, const fs::path& b) { return a.filename().u8string() < b.filename().u8string(); });
    Planner planner(error);
    if (!planner.start(safe_component(root_name), std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()))
        return std::nullopt;
    std::set<std::string> used;
    for (fs::path s : chosen) {
        if (!s.has_filename()) s = s.parent_path();
        // Something the user picked is followed if it is a link (they chose it); links inside folders never are.
        if (!planner.add_source(s, planner.plan.root, unique_in(safe_component(s.filename().u8string()), used), true)) return std::nullopt;
    }
    if (planner.plan.items.size() == 1) {
        error = "None of the chosen items can be sent (links and special files are left out).";
        return std::nullopt;
    }
    if (!planner.finish()) return std::nullopt;
    return std::move(planner.plan);
}

bool write(const Plan& plan, const fs::path& out, const Progress& progress, std::string& error, Bytes* sha256) {
    std::error_code ec;
    const fs::path dir = out.has_parent_path() ? out.parent_path() : fs::path(".");
    const auto space = fs::space(dir, ec);
    if (!ec && space.available < plan.archive_bytes) {
        error = "There isn't enough free space to pack these files: they need " + size_text(plan.archive_bytes) + " and there is " +
                size_text(space.available) + ".";
        return false;
    }
    std::ofstream o(out, std::ios::binary | std::ios::trunc);
    if (!o) {
        error = "Couldn't create " + out.u8string();
        return false;
    }
    auto remove_partial = make_scope_exit([&] {
        o.close();
        std::error_code rm;
        fs::remove(out, rm);
    });
    uint64_t written = 0;
    attachment::Sha256 hash;
    auto put = [&](const uint8_t* p, size_t n) {
        o.write(reinterpret_cast<const char*>(p), static_cast<std::streamsize>(n));
        if (sha256) hash.update(p, n);
        written += n;
        return static_cast<bool>(o);
    };
    std::vector<uint8_t> buf(COPY_BYTES);
    for (const Item& item : plan.items) {
        const Bytes h = detail::entry_header(item.path, item.dir, item.size, item.mtime);
        if (!put(h.data(), h.size())) break;
        if (item.dir) continue;
        std::ifstream in(item.source, std::ios::binary);
        if (!in) {
            error = "Couldn't open " + item.source.u8string();
            return false;
        }
        for (uint64_t left = item.size; left > 0;) {
            const size_t n = static_cast<size_t>(std::min<uint64_t>(left, buf.size()));
            in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
            if (in.gcount() != static_cast<std::streamsize>(n)) {
                error = item.source.u8string() + " got smaller while it was being packed. Try again once it's finished changing.";
                return false;
            }
            if (!put(buf.data(), n)) break;
            left -= n;
            if (progress && !progress(written, plan.archive_bytes)) {
                error = "Cancelled.";
                return false;
            }
        }
        if (in.peek() != std::char_traits<char>::eof()) {
            error = item.source.u8string() + " got larger while it was being packed. Try again once it's finished changing.";
            return false;
        }
        const Bytes pad(static_cast<size_t>(detail::padding(item.size)), 0);
        if (!put(pad.data(), pad.size())) break;
    }
    const Bytes end = detail::end_of_archive();
    put(end.data(), end.size());
    o.flush();
    if (!o || written != plan.archive_bytes) {
        error = "Couldn't write the packed file " + out.u8string() + " (is the disk full?)";
        return false;
    }
    o.close();
    if (!o) {
        error = "Couldn't write the packed file " + out.u8string();
        return false;
    }
    if (progress) progress(written, plan.archive_bytes);
    if (sha256) *sha256 = hash.finish();
    remove_partial.dismiss();
    return true;
}

bool is_pack_name(const std::string& file_name) {
    const size_t n = std::strlen(NAME_SUFFIX);
    return file_name.size() > n && file_name.compare(file_name.size() - n, n, NAME_SUFFIX) == 0;
}

bool scan(std::istream& in, uint64_t total, std::vector<Entry>& entries, std::string& error) {
    return scan_impl(in, total, entries, error, [](const Entry& e, Reader& r, std::string& err) {
        if (r.skip(e.size)) return true;
        err = "it ends too early";
        return false;
    });
}

std::optional<Unpacked> unpack(const fs::path& archive, const fs::path& directory, const Progress& progress, std::string& error) {
    std::error_code ec;
    const uint64_t total = fs::file_size(archive, ec);
    if (ec) {
        error = "Couldn't read " + archive.u8string() + ": " + ec.message();
        return std::nullopt;
    }
    std::ifstream in(archive, std::ios::binary);
    if (!in) {
        error = "Couldn't open " + archive.u8string();
        return std::nullopt;
    }
    // First the whole archive is checked, writing nothing.
    std::vector<Entry> entries;
    std::string why;
    if (!scan(in, total, entries, why)) {
        error = "These files can't be unpacked: " + why + ".";
        return std::nullopt;
    }
    Unpacked result;
    for (size_t i = 1; i < entries.size(); i++) {
        (entries[i].dir ? result.folders : result.files)++;
        result.content_bytes += entries[i].size;
    }
    const auto space = fs::space(directory, ec);
    if (!ec && space.available < result.content_bytes) {
        error = "There isn't enough free space to unpack these files: they need " + size_text(result.content_bytes) + " and there is " +
                size_text(space.available) + ".";
        return std::nullopt;
    }

    // Then it is unpacked into a hidden folder of its own, made fresh here, so nothing in it can be a link or anything
    // else that was already there.
    const std::string root = entries[0].path;
    const fs::path temp = attachment::unique_path(directory, "." + root + ".unpacking");
    if (temp.empty() || !fs::create_directory(temp, ec) || ec) {
        error = "Couldn't create a folder in " + directory.u8string();
        return std::nullopt;
    }
    auto remove_partial = make_scope_exit([&] {
        std::error_code rm;
        fs::remove_all(temp, rm);
    });
    in.clear();
    in.seekg(0);
    uint64_t done = 0;
    std::vector<std::pair<fs::path, int64_t>> folder_times;
    std::vector<uint8_t> buf(COPY_BYTES);
    const Visitor extract = [&](const Entry& e, Reader& r, std::string& err) {
        fs::path target = temp;
        if (e.path.size() > root.size()) {
            const std::string rel = e.path.substr(root.size() + 1);
            for (size_t start = 0;;) {
                const size_t slash = rel.find('/', start);
                target /= fs::u8path(rel.substr(start, slash == std::string::npos ? std::string::npos : slash - start));
                if (slash == std::string::npos) break;
                start = slash + 1;
            }
        }
        std::error_code fec;
        if (e.dir) {
            if (target != temp && (!fs::create_directory(target, fec) || fec)) {
                err = "a folder couldn't be created";
                return false;
            }
            folder_times.emplace_back(target, e.mtime);
            return true;
        }
        if (fs::symlink_status(target, fec).type() != fs::file_type::not_found) {
            err = "two entries have the same name";
            return false;
        }
        std::ofstream out(target, std::ios::binary);
        if (!out) {
            err = "a file couldn't be created";
            return false;
        }
        for (uint64_t left = e.size; left > 0;) {
            const size_t n = static_cast<size_t>(std::min<uint64_t>(left, buf.size()));
            if (!r.read(buf.data(), n)) {
                err = "it ends too early";
                return false;
            }
            out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(n));
            if (!out) {
                err = "a file couldn't be written (is the disk full?)";
                return false;
            }
            left -= n;
            done += n;
            if (progress && !progress(done, result.content_bytes)) {
                err = "cancelled";
                return false;
            }
        }
        out.close();
        if (!out) {
            err = "a file couldn't be written (is the disk full?)";
            return false;
        }
        fs::last_write_time(target, from_unix(e.mtime), fec);  // best effort
        return true;
    };
    if (!scan_impl(in, total, entries, why, extract)) {
        error = why == "cancelled" ? "Cancelled." : "These files can't be unpacked: " + why + ".";
        return std::nullopt;
    }
    // Folders' dates last (writing into a folder changes its date), innermost first.
    for (auto it = folder_times.rbegin(); it != folder_times.rend(); ++it) fs::last_write_time(it->first, from_unix(it->second), ec);

    // Finally the folder gets its real name: the top folder's, or "name (2)"... if that is taken.
    for (int attempt = 0; attempt < 3; attempt++) {
        const fs::path final_path = attachment::unique_path(directory, root);
        if (final_path.empty()) break;
        fs::rename(temp, final_path, ec);
        if (!ec) {
            remove_partial.dismiss();
            result.saved = final_path;
            if (progress) progress(result.content_bytes, result.content_bytes);
            return result;
        }
    }
    error = "Couldn't move the unpacked files into place in " + directory.u8string();
    return std::nullopt;
}

}  // namespace file_pack
