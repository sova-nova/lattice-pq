// Tests for packing files and folders into one file and unpacking them (bulk transfers): round trips, compatibility
// with the system's tar, the sending side's rules (links, names, limits, files that change), and hostile archives,
// each of which must be refused without leaving anything behind.
#include "file_pack.h"

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>

namespace fs = std::filesystem;
using file_pack::Bytes;

static int failures = 0;
#define CHECK(c, msg)                                                  \
    do {                                                               \
        if (c) std::cout << "  PASS " << (msg) << "\n";                \
        else { std::cout << "  FAIL " << (msg) << "\n"; failures++; } \
    } while (0)

static fs::path temp_root;

static fs::path fresh_dir(const std::string& name) {
    const fs::path p = temp_root / name;
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

static void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
}

static std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

static std::string random_bytes(size_t n, unsigned seed) {
    std::mt19937 rng(seed);
    std::string s(n, '\0');
    for (char& c : s) c = static_cast<char>(rng());
    return s;
}

// Everything under `dir`: relative path -> contents ("<dir>" for folders).
static std::map<std::string, std::string> snapshot(const fs::path& dir) {
    std::map<std::string, std::string> out;
    for (auto it = fs::recursive_directory_iterator(dir); it != fs::recursive_directory_iterator(); ++it) {
        const std::string rel = fs::relative(it->path(), dir).u8string();
        out[rel] = it->is_directory() ? "<dir>" : read_file(it->path());
    }
    return out;
}

static size_t count_entries(const fs::path& dir) {
    size_t n = 0;
    for (auto it = fs::directory_iterator(dir); it != fs::directory_iterator(); ++it) n++;
    return n;
}

// --- Building archives by hand, for the hostile cases ---

struct Raw {
    Bytes bytes;
    // An entry as the writer would lay it out, data and padding included.
    Raw& add(const std::string& path, bool dir, const std::string& data = "", int64_t mtime = 1700000000) {
        const Bytes h = file_pack::detail::entry_header(path, dir, data.size(), mtime);
        bytes.insert(bytes.end(), h.begin(), h.end());
        bytes.insert(bytes.end(), data.begin(), data.end());
        bytes.insert(bytes.end(), static_cast<size_t>(file_pack::detail::padding(data.size())), 0);
        return *this;
    }
    Raw& end() {
        const Bytes e = file_pack::detail::end_of_archive();
        bytes.insert(bytes.end(), e.begin(), e.end());
        return *this;
    }
};

// Recomputes the checksum of the header block starting at `at`, after it was changed on purpose.
static void fix_checksum(Bytes& b, size_t at) {
    for (size_t i = 0; i < 8; i++) b[at + 148 + i] = ' ';
    unsigned sum = 0;
    for (size_t i = 0; i < 512; i++) sum += b[at + i];
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%06o", sum);
    for (size_t i = 0; i < 6; i++) b[at + 148 + i] = static_cast<uint8_t>(buf[i]);
    b[at + 154] = 0;
    b[at + 155] = ' ';
}

// "<length> key=value\n" with the right length.
static std::string pax(const std::string& key, const std::string& value) {
    const std::string body = " " + key + "=" + value + "\n";
    size_t len = body.size() + 1;
    while (std::to_string(len).size() + body.size() != len) len = std::to_string(len).size() + body.size();
    return std::to_string(len) + body;
}

static bool scans(const Bytes& b, std::string* why = nullptr) {
    std::istringstream in(std::string(b.begin(), b.end()));
    std::vector<file_pack::Entry> entries;
    std::string error;
    const bool ok = file_pack::scan(in, b.size(), entries, error);
    if (why) *why = error;
    return ok;
}

// Hostile names hold control characters and invalid UTF-8: shown as \xNN so the output stays readable text.
static std::string printable(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c >= 0x20 && c < 0x7f) out += static_cast<char>(c);
        else {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        }
    }
    return out;
}

static void refused(const std::string& what, const Bytes& b) {
    std::string why;
    const bool ok = scans(b, &why);
    CHECK(!ok, printable("refused: " + what + (ok ? "" : " (" + why + ")")));
}

int main() {
    temp_root = fs::temp_directory_path() / ("pq-test-pack-" + std::to_string(std::random_device{}()));
    fs::create_directories(temp_root);

    std::cout << "Packing a folder and unpacking it\n";
    const fs::path src = fresh_dir("src") / "Photos";
    write_file(src / "a.txt", "hello");
    write_file(src / "empty.bin", "");
    write_file(src / "sub" / "b.bin", random_bytes(300 * 1024 + 7, 1));
    write_file(src / "sub" / "deeper" / "c.txt", "deep");
    fs::create_directories(src / "emptydir");
    write_file(src / ".hidden", "dotfile");
    write_file(src / u8"ünïcödé ñame.txt", "unicode");
    const std::string long_dir(60, 'x'), long_file(60, 'y');
    write_file(src / long_dir / (long_file + ".txt"), "long path");
    fs::last_write_time(src / "a.txt", fs::last_write_time(src / "a.txt") - std::chrono::hours(24 * 400));
    const auto a_time = fs::last_write_time(src / "a.txt");

    std::string error;
    auto plan = file_pack::plan_folder(src, error);
    CHECK(plan.has_value(), "a folder is planned (" + error + ")");
    if (!plan) return 1;
    CHECK(plan->root == "Photos", "the top folder is the folder's name");
    CHECK(plan->file_name() == "Photos.lattice.tar", "the pack is named <top folder>.lattice.tar");
    CHECK(plan->files == 7 && plan->folders == 4, "7 files and 4 folders are counted (" + std::to_string(plan->files) + ", " + std::to_string(plan->folders) + ")");
    CHECK(plan->items.front().path == "Photos" && plan->items.front().dir, "the top folder comes first");
    CHECK(plan->skipped.empty(), "nothing is skipped");

    const fs::path out_dir = fresh_dir("out");
    const fs::path pack = out_dir / plan->file_name();
    uint64_t last_progress = 0;
    CHECK(file_pack::write(*plan, pack, [&](uint64_t done, uint64_t) { last_progress = done; return true; }, error), "the pack is written (" + error + ")");
    CHECK(fs::file_size(pack) == plan->archive_bytes, "its size is exactly what the plan said");
    CHECK(last_progress == plan->archive_bytes, "progress reaches the end");
    CHECK(file_pack::is_pack_name(pack.filename().u8string()), "its name is recognised as a pack");
    CHECK(!file_pack::is_pack_name("Photos.tar") && !file_pack::is_pack_name(".lattice.tar"), "other names are not");

    const fs::path dest = fresh_dir("dest");
    auto un = file_pack::unpack(pack, dest, nullptr, error);
    CHECK(un.has_value(), "it unpacks (" + error + ")");
    if (!un) return 1;
    CHECK(un->saved == dest / "Photos", "into a folder named after the top folder");
    CHECK(un->files == 7 && un->folders == 4 && un->content_bytes == plan->content_bytes, "the counts match");
    CHECK(snapshot(un->saved) == snapshot(src), "every file and folder comes back exactly, with its path");
    CHECK(std::chrono::duration_cast<std::chrono::seconds>(fs::last_write_time(un->saved / "a.txt") - a_time).count() == 0,
          "a file's date is kept");
    auto again = file_pack::unpack(pack, dest, nullptr, error);
    CHECK(again && again->saved == dest / "Photos (2)", "unpacking again doesn't touch the first copy: \"Photos (2)\"");
    CHECK(count_entries(dest) == 2, "nothing else is left in the folder (no hidden working folder)");

    std::cout << "Other tools can open it\n";
    if (std::system("tar --version > /dev/null 2>&1") == 0) {
        const fs::path by_tar = fresh_dir("by-tar");
        const std::string cmd = "tar -xf '" + pack.string() + "' -C '" + by_tar.string() + "'";
        CHECK(std::system(cmd.c_str()) == 0, "the system's tar extracts it");
        CHECK(snapshot(by_tar / "Photos") == snapshot(src), "and gets the same files (long and non-ASCII paths included)");
    } else {
        std::cout << "  (no tar here: skipped)\n";
    }

    std::cout << "Choosing several things to send\n";
    {
        const fs::path base = fresh_dir("items");
        write_file(base / "one" / "a.txt", "first a");
        write_file(base / "two" / "a.txt", "second a");
        write_file(base / "folder" / "inner.txt", "inner");
        write_file(base / "outside-secret.txt", "secret");
        fs::create_symlink(base / "outside-secret.txt", base / "folder" / "link-to-secret");
        fs::create_symlink(base / "outside-secret.txt", base / "chosen-link");
        write_file(base / "folder" / "Read.me", "upper");
        write_file(base / "folder" / "read.me", "lower");
        write_file(base / "folder" / "bad:name?.txt", "bad");
        write_file(base / "folder" / "trail.", "trail");
        write_file(base / "folder" / "con", "device name");
        auto p = file_pack::plan_items("My files", {base / "one" / "a.txt", base / "two" / "a.txt", base / "folder", base / "one" / "a.txt", base / "chosen-link"}, error);
        CHECK(p.has_value(), "several items are planned (" + error + ")");
        if (p) {
            std::map<std::string, const file_pack::Item*> by_path;
            for (const auto& i : p->items) by_path[i.path] = &i;
            CHECK(p->root == "My files", "the top folder is the name given");
            CHECK(by_path.count("My files/a.txt") && by_path.count("My files/a (2).txt"), "two files with the same name both go, one as \"a (2).txt\"");
            CHECK(by_path.count("My files/chosen-link"), "a link the user chose directly is followed");
            CHECK(p->skipped.size() == 1 && p->skipped[0].filename() == "link-to-secret", "a link inside a folder is left out and reported, not followed");
            CHECK(by_path.count("My files/folder/Read.me") && by_path.count("My files/folder/read (2).me"), "names differing only in case are made distinct");
            CHECK(by_path.count("My files/folder/bad_name_.txt"), "characters Windows forbids are replaced");
            CHECK(by_path.count("My files/folder/trail"), "a trailing dot is dropped");
            CHECK(by_path.count("My files/folder/_con"), "a Windows device name is changed");
            CHECK(p->files == 9, "the same file chosen twice goes once (9 files, got " + std::to_string(p->files) + ")");
            const fs::path pk = out_dir / "items.lattice.tar";
            CHECK(file_pack::write(*p, pk, nullptr, error), "it is written");
            auto u = file_pack::unpack(pk, fresh_dir("items-dest"), nullptr, error);
            CHECK(u && read_file(u->saved / "a (2).txt") == "second a" && read_file(u->saved / "chosen-link") == "secret",
                  "and unpacks with the right contents under the new names");
        }
        CHECK(!file_pack::plan_items("x", {}, error), "nothing chosen: refused");
        CHECK(!file_pack::plan_items("x", {base / "does-not-exist"}, error), "something that doesn't exist: refused");
    }

    std::cout << "Limits when sending\n";
    {
        const fs::path many = fresh_dir("many") / "Many";
        fs::create_directories(many);
        for (size_t i = 0; i <= file_pack::MAX_ENTRIES; i++) std::ofstream(many / ("f" + std::to_string(i)));
        CHECK(!file_pack::plan_folder(many, error), "more than 10,000 entries: refused (" + error + ")");
        fs::remove(many / "f0");
        CHECK(file_pack::plan_folder(many, error).has_value(), "exactly 10,000: allowed");

        fs::path deep = fresh_dir("deep") / "D";
        fs::path d = deep;
        for (size_t i = 1; i < file_pack::MAX_DEPTH; i++) d /= "d";
        fs::create_directories(d);
        CHECK(file_pack::plan_folder(deep, error).has_value(), "32 levels: allowed");
        fs::create_directories(d / "d");
        CHECK(!file_pack::plan_folder(deep, error), "33 levels: refused (" + error + ")");

        const fs::path big = fresh_dir("big") / "Big";
        fs::create_directories(big);
        std::ofstream(big / "huge.bin").close();
        fs::resize_file(big / "huge.bin", file_pack::MAX_PACK_BYTES);  // sparse: takes no space
        CHECK(!file_pack::plan_folder(big, error), "more than 5 GiB in all: refused before reading anything (" + error + ")");
    }

    std::cout << "Files that change while being packed\n";
    {
        const fs::path f = fresh_dir("change") / "C";
        write_file(f / "x.txt", "12345");
        auto p = file_pack::plan_folder(f, error);
        const fs::path pk = out_dir / "change.lattice.tar";
        write_file(f / "x.txt", "123456789");
        CHECK(!file_pack::write(*p, pk, nullptr, error) && !fs::exists(pk), "a file that grew: refused, nothing left (" + error + ")");
        write_file(f / "x.txt", "12");
        CHECK(!file_pack::write(*p, pk, nullptr, error) && !fs::exists(pk), "a file that shrank: refused, nothing left");
    }

    std::cout << "Cancelling\n";
    {
        const fs::path pk = out_dir / "cancel.lattice.tar";
        CHECK(!file_pack::write(*plan, pk, [](uint64_t, uint64_t) { return false; }, error) && !fs::exists(pk), "cancelled packing leaves nothing");
        const fs::path d = fresh_dir("cancel-dest");
        CHECK(!file_pack::unpack(pack, d, [](uint64_t done, uint64_t) { return done == 0; }, error) && count_entries(d) == 0,
              "cancelled unpacking (part-way) leaves nothing");
    }

    std::cout << "An existing name is never replaced\n";
    {
        const fs::path d = fresh_dir("existing");
        write_file(d / "Photos", "a file, not a folder");
        auto u = file_pack::unpack(pack, d, nullptr, error);
        CHECK(u && u->saved == d / "Photos (2)" && read_file(d / "Photos") == "a file, not a folder", "a file with the top folder's name is left alone");
    }

    std::cout << "Hostile archives\n";
    const std::string data = "data";
    Raw good;
    good.add("Top", true).add("Top/sub", true).add("Top/sub/f.txt", false, data).add("Top/.ok", false).end();
    CHECK(scans(good.bytes), "the baseline is accepted");
    for (const char* bad : {"Top/..", "Top/.", "Top/../x", "Top/..hidden", "Top/a\\b", "Top/CON", "Top/c:", "Top/x.", "Top/ x",
                            "Top/a\x01" "b", "Top/a\xff" "b", "Top/\xe2\x80\xae" "gpj.exe", "Top//x"}) {
        Raw r;
        r.add("Top", true).add(bad, false, data).end();
        refused(std::string("the name \"") + bad + "\"", r.bytes);
    }
    { Raw r; r.add("/etc", true).add("/etc/passwd", false, data).end(); refused("an absolute path", r.bytes); }
    for (char type : {'1', '2', '3', '4', '6', '7', 'g', 'L', 'K'}) {
        Raw r;
        r.add("Top", true).add("Top/link", false).end();
        const size_t at = 512;
        r.bytes[at + 156] = static_cast<uint8_t>(type);
        fix_checksum(r.bytes, at);
        refused(std::string("an entry of type '") + type + "'", r.bytes);
    }
    { Raw r; r.add("Top", true).add("Top/x", false, data).add("Top/x", false, data).end(); refused("the same path twice", r.bytes); }
    { Raw r; r.add("Top", true).add("Top/Readme", false, data).add("Top/README", false, data).end(); refused("paths differing only in case", r.bytes); }
    { Raw r; r.add("Top", true).add("Top/sub/x", false, data).end(); refused("a file before its folder", r.bytes); }
    { Raw r; r.add("Top", true).add("Other", true).end(); refused("two top folders", r.bytes); }
    { Raw r; r.add("Top", true).add("Other/x", false, data).end(); refused("an entry outside the top folder", r.bytes); }
    { Raw r; r.add("Top", false, data).end(); refused("a top that is a file", r.bytes); }
    { Raw r; r.add("Top", true).add("Top/sub", true).add("Top/sub", false, data).end(); refused("a file with a folder's name", r.bytes); }
    {
        Raw r;
        std::string p = "Top";
        r.add(p, true);
        for (size_t i = 1; i <= file_pack::MAX_DEPTH; i++) { p += "/d"; r.add(p, true); }
        r.end();
        refused("33 levels", r.bytes);
    }
    {
        Raw r;
        std::string p = "Top";
        r.add(p, true);
        for (int i = 0; i < 6; i++) { p += "/" + std::string(190, 'n'); r.add(p, true); }
        r.end();
        refused("a path longer than 1,024 bytes", r.bytes);
    }
    {
        Raw r;
        r.add("Top", true);
        for (size_t i = 0; i <= file_pack::MAX_ENTRIES; i++) r.add("Top/f" + std::to_string(i), false);
        r.end();
        refused("more than 10,000 entries", r.bytes);
        Raw ok;
        ok.add("Top", true);
        for (size_t i = 0; i < file_pack::MAX_ENTRIES; i++) ok.add("Top/f" + std::to_string(i), false);
        ok.end();
        CHECK(scans(ok.bytes), "exactly 10,000 entries are accepted");
    }
    auto patched = [&](size_t at, uint8_t value, bool fix) {
        Raw r;
        r.add("Top", true).add("Top/f.txt", false, data).end();
        r.bytes[at] = value;
        if (fix) fix_checksum(r.bytes, at - at % 512);
        return r.bytes;
    };
    refused("a wrong checksum", patched(512 + 0, 'G', false));
    refused("an owner other than 0", patched(512 + 108 + 6, '1', true));
    refused("permissions other than the writer's", patched(512 + 100 + 4, '7', true));
    refused("a size field that isn't octal", patched(512 + 124 + 3, '9', true));
    refused("a user name", patched(512 + 265, 'r', true));
    refused("a link target", patched(512 + 157, 'x', true));
    refused("a name prefix", patched(512 + 345, 'p', true));
    refused("other magic", patched(512 + 257, 'g', true));
    refused("a name with junk after its end", patched(512 + 50, 'j', true));
    refused("data in the padding", patched(1024 + 10, 1, false));
    {
        Raw r;
        r.add("Top", true).add("Top/d", true).end();
        r.bytes[512 + 124 + 10] = '1';
        fix_checksum(r.bytes, 512);
        refused("a folder with a size", r.bytes);
    }
    { Raw r; r.add("Top", true).add("Top/f/", false).end(); refused("a file whose name ends in a slash", r.bytes); }
    {
        Bytes b = good.bytes;
        b.resize(b.size() - 1);
        refused("a truncated archive", b);
        Bytes c = good.bytes;
        c.resize(c.size() - 1024);
        refused("no end blocks", c);
        Bytes d = good.bytes;
        d.push_back(0);
        refused("data after the end", d);
        Bytes e = good.bytes;
        e.insert(e.end(), 512, 0);
        refused("a third zero block", e);
        Bytes f = good.bytes;
        f.resize(f.size() - 512);
        refused("only one end block", f);
    }
    { Raw r; r.end(); refused("an empty archive", r.bytes); }
    refused("nothing at all", Bytes());
    {
        std::istringstream in("");
        std::vector<file_pack::Entry> e;
        CHECK(!file_pack::scan(in, file_pack::MAX_PACK_BYTES + 1, e, error) && error.find("larger than") != std::string::npos,
              "refused: larger than 5 GiB, before reading anything (" + error + ")");
    }
    // pax records: only exactly the one the writer makes.
    auto with_pax = [&](const std::string& record) {
        Raw r;
        r.add("Top", true);
        Bytes x = file_pack::detail::entry_header("PaxHeader", false, record.size(), 0);  // borrow a header block...
        x[156] = 'x';                                                                   // ...and make it a pax header
        fix_checksum(x, 0);
        r.bytes.insert(r.bytes.end(), x.begin(), x.end());
        r.bytes.insert(r.bytes.end(), record.begin(), record.end());
        r.bytes.insert(r.bytes.end(), static_cast<size_t>(file_pack::detail::padding(record.size())), 0);
        const Bytes h = file_pack::detail::entry_header("Top/short.txt", false, 0, 1700000000);
        r.bytes.insert(r.bytes.end(), h.begin(), h.end());
        r.end();
        return r.bytes;
    };
    refused("a pax header for a short ASCII name (not how the writer does it)", with_pax(pax("path", "Top/short.txt")));
    {
        std::string wrong = pax("path", "Top/short.txt");
        wrong[1] = static_cast<char>(wrong[1] + 1);
        refused("a pax record with the wrong length", with_pax(wrong));
    }
    refused("a pax record for something other than the path", with_pax(pax("mtime", "1700000000")));
    refused("two pax records", with_pax(pax("path", "Top/short.txt") + pax("mtime", "1700000000")));
    refused("a pax path that escapes", with_pax(pax("path", "Top/../x.txt")));
    // Malformed records must be refused, not read past their end.
    for (const char* rec : {"x", "1 ", "5 pat\n", "7 path=", "6 path=", "8 path=\n", "  path=x\n", "9 path=x\n\n"})
        refused(std::string("a malformed pax record \"") + rec + "\"", with_pax(rec));

    std::cout << "A refused archive leaves nothing behind\n";
    {
        Raw r;
        r.add("Top", true);
        for (int i = 0; i < 20; i++) r.add("Top/fine" + std::to_string(i) + ".txt", false, "fine");
        r.add("Top/../escape.txt", false, "escaped").end();
        const fs::path pk = out_dir / "hostile.lattice.tar";
        std::ofstream(pk, std::ios::binary).write(reinterpret_cast<const char*>(r.bytes.data()), static_cast<std::streamsize>(r.bytes.size()));
        const fs::path d = fresh_dir("hostile-dest") / "inner";
        fs::create_directories(d);
        CHECK(!file_pack::unpack(pk, d, nullptr, error), "a traversal after 20 good files is refused (" + error + ")");
        CHECK(count_entries(d) == 0 && !fs::exists(d.parent_path() / "escape.txt"), "nothing was written, inside or outside");
    }

    fs::remove_all(temp_root);
    std::cout << (failures ? "FAILED: " + std::to_string(failures) : std::string("All passed")) << "\n";
    return failures ? 1 : 0;
}
