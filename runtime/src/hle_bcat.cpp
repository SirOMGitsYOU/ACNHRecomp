// nn::bcat (data delivered by the console's servers: events, news) at the API level.
//
// The delivery cache is a folder on this computer: <data root>/bcat/<title id>/<directory>/<file>, with index.txt
// listing each file's size and digest. Playing on Rustendo, the folder is synced from the server's /api/bcat once per
// boot (the first MountDeliveryCacheStorage starts it and waits for it, at most kSyncWaitSeconds), so the game
// gets the events the server delivers today; offline, it keeps the last synced files, as a console keeps its cache.
// Not on Rustendo, or never synced, the cache is empty, like a console that has never been online.
//
// RequestSyncDeliveryCache is still refused: the game then reads the cache as it is, and the sync above has already
// filled it (a success would make the game drive DeliveryCacheProgress, whose IPC side does not exist here).
//
// DeliveryCacheDirectory and DeliveryCacheFile objects live in game memory; what each has open is kept here, by the
// object's address, and dropped by its destructor (the SDK's own destructor only closes an IPC session, never opened).
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <nx/runtime.h>

#include "nextendo.h"
#include "platform.h"

namespace nx {

namespace {

namespace fs = std::filesystem;

// nn::bcat results: module 122. ResultNotFound (description 30), ResultInternetRequestNotAccepted (description 2).
constexpr uint32_t kNotFound = 122 | (30u << 9);
constexpr uint32_t kNoInternet = 122 | (2u << 9);

constexpr int kSyncWaitSeconds = 15;
constexpr size_t kNameSize = 32;    // DirectoryName, FileName: char[32]
constexpr size_t kEntrySize = 0x38; // DeliveryCacheDirectoryEntry: FileName, int64 size (+0x20), Digest (+0x28)

struct File {
    std::string name;
    uint64_t size = 0;
    uint8_t digest[16] = {};
};

std::mutex g_lock;
std::condition_variable g_cv;
bool g_synced = false;
std::map<std::string, std::vector<File>> g_cache;  // directory -> files, from index.txt
std::map<uint64_t, std::string> g_dirs;            // DeliveryCacheDirectory object -> its directory
std::map<uint64_t, std::pair<std::string, File>> g_files;  // DeliveryCacheFile object -> directory, file

fs::path cache_dir() {
    char id[17];
    std::snprintf(id, sizeof id, "%016llx", (unsigned long long)nextendo::kAcnhTitleId);
    return fs::u8path(plat::data_root()) / "bcat" / id;
}

// Server names become paths: the server's own rule (1-31 of [A-Za-z0-9_.-], not . or ..).
bool valid_name(const std::string& s) {
    if (s.empty() || s.size() > 31 || s == "." || s == "..") return false;
    for (char ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-' && ch != '.') return false;
    return true;
}

bool parse_digest(const std::string& hex, uint8_t out[16]) {
    if (hex.size() != 32) return false;
    for (int i = 0; i < 16; i++) {
        unsigned v = 0;
        if (std::sscanf(hex.c_str() + 2 * i, "%2x", &v) != 1) return false;
        out[i] = uint8_t(v);
    }
    return true;
}

// index.txt: one "<directory> <file> <size> <digest hex>" line per file.
std::vector<nextendo::BcatFile> read_index(const fs::path& dir) {
    std::vector<nextendo::BcatFile> out;
    std::ifstream in(dir / "index.txt");
    for (std::string line; std::getline(in, line);) {
        std::istringstream ls(line);
        nextendo::BcatFile f;
        if (ls >> f.directory >> f.name >> f.size >> f.digest) out.push_back(f);
    }
    return out;
}

void load_cache() {
    std::map<std::string, std::vector<File>> cache;
    for (const auto& f : read_index(cache_dir())) {
        File e{f.name, f.size, {}};
        if (valid_name(f.directory) && valid_name(f.name) && parse_digest(f.digest, e.digest))
            cache[f.directory].push_back(e);
    }
    std::lock_guard<std::mutex> l(g_lock);
    g_cache = std::move(cache);
    g_synced = true;
    g_cv.notify_all();
}

// Downloads what changed into <title>.new, then swaps it in for the old folder. Files whose digest did not change are
// copied from the old folder.
void sync() {
    if (!nextendo::is_rustendo()) return;
    std::vector<nextendo::BcatFile> list;
    std::string err;
    if (!nextendo::bcat_list(nextendo::kAcnhTitleId, list, err)) {
        log("bcat: cannot reach Rustendo (%s): the last synced delivery cache is used", err.c_str());
        return;
    }
    const fs::path dir = cache_dir(), next = dir.string() + ".new";
    std::map<std::string, std::string> old;  // "dir/name" -> digest
    for (const auto& f : read_index(dir)) old[f.directory + "/" + f.name] = f.digest;
    std::error_code ec;
    fs::remove_all(next, ec);
    fs::create_directories(next, ec);
    std::ofstream index(next / "index.txt", std::ios::trunc);
    size_t fetched = 0;
    for (const auto& f : list) {
        if (!valid_name(f.directory) || !valid_name(f.name)) continue;
        fs::create_directories(next / f.directory, ec);
        const fs::path to = next / f.directory / f.name;
        const auto it = old.find(f.directory + "/" + f.name);
        if (it == old.end() || it->second != f.digest || !fs::copy_file(dir / f.directory / f.name, to, ec)) {
            std::string bytes;
            if (!nextendo::bcat_get(nextendo::kAcnhTitleId, f.directory, f.name, bytes, err)) {
                log("bcat: cannot download %s/%s (%s): the last synced delivery cache is used", f.directory.c_str(),
                    f.name.c_str(), err.c_str());
                fs::remove_all(next, ec);
                return;
            }
            std::ofstream(to, std::ios::binary | std::ios::trunc).write(bytes.data(), std::streamsize(bytes.size()));
            fetched++;
        }
        index << f.directory << ' ' << f.name << ' ' << f.size << ' ' << f.digest << '\n';
    }
    index.close();
    fs::remove_all(dir, ec);
    fs::rename(next, dir, ec);
    if (ec) log("bcat: cannot replace the delivery cache: %s", ec.message().c_str());
    log("bcat: delivery cache synced from Rustendo: %zu files, %zu downloaded", list.size(), fetched);
}

void wait_synced() {
    std::unique_lock<std::mutex> l(g_lock);
    g_cv.wait_for(l, std::chrono::seconds(kSyncWaitSeconds), [] { return g_synced; });
}

std::string name_at(uint64_t addr) {
    const char* p = reinterpret_cast<const char*>(addr);
    return std::string(p, strnlen(p, kNameSize));
}

void ok(CPU& c) { c.x[0] = 0; }
void no_internet(CPU& c) { c.x[0] = kNoInternet; }

// The sync runs once per boot, on its own thread.
void start_sync() {
    static std::once_flag once;
    std::call_once(once, [] {
        std::thread([] {
            sync();
            load_cache();
        }).detach();
    });
}

// Result nn::bcat::Initialize()
void Initialize(CPU& c) {
    start_sync();
    c.x[0] = 0;
}

// Result MountDeliveryCacheStorage(): waits for the sync (ACNH mounts without calling Initialize first).
void Mount(CPU& c) {
    start_sync();
    wait_synced();
    c.x[0] = 0;
}

// Result DeliveryCacheDirectory::Open(const DirectoryName&)
void DirectoryOpen(CPU& c) {
    const std::string name = name_at(c.x[1]);
    std::lock_guard<std::mutex> l(g_lock);
    const bool found = g_cache.count(name) != 0;
    if (found) g_dirs[c.x[0]] = name;
    log("bcat: open directory %s: %s", name.c_str(), found ? "found" : "not found");
    c.x[0] = found ? 0 : kNotFound;
}

// Result DeliveryCacheDirectory::Read(int* count, DeliveryCacheDirectoryEntry*, int max)
void DirectoryRead(CPU& c) {
    std::lock_guard<std::mutex> l(g_lock);
    const auto d = g_dirs.find(c.x[0]);
    int n = 0;
    const auto dir = d == g_dirs.end() ? g_cache.end() : g_cache.find(d->second);
    if (dir != g_cache.end()) {
        const auto& files = dir->second;
        const int max = int32_t(c.x[3]);
        for (; n < max && n < int(files.size()); n++) {
            const uint64_t e = c.x[2] + uint64_t(n) * kEntrySize;
            std::memset(reinterpret_cast<void*>(e), 0, kEntrySize);
            std::memcpy(reinterpret_cast<void*>(e), files[n].name.data(), files[n].name.size());
            st<int64_t>(e + 0x20, int64_t(files[n].size));
            std::memcpy(reinterpret_cast<void*>(e + 0x28), files[n].digest, 16);
        }
    }
    if (c.x[1]) st<int32_t>(c.x[1], n);
    c.x[0] = d != g_dirs.end() ? 0 : kNotFound;
}

// DeliveryCacheDirectory::~DeliveryCacheDirectory()
void DirectoryDestroy(CPU& c) {
    std::lock_guard<std::mutex> l(g_lock);
    g_dirs.erase(c.x[0]);
}

// Result DeliveryCacheFile::Open(const DirectoryName&, const FileName&)
void FileOpen(CPU& c) {
    const std::string dir = name_at(c.x[1]), name = name_at(c.x[2]);
    std::lock_guard<std::mutex> l(g_lock);
    const auto d = g_cache.find(dir);
    if (d != g_cache.end())
        for (const File& f : d->second)
            if (f.name == name) {
                g_files[c.x[0]] = {dir, f};
                log("bcat: open file %s/%s (%llu bytes)", dir.c_str(), name.c_str(), (unsigned long long)f.size);
                c.x[0] = 0;
                return;
            }
    log("bcat: open file %s/%s: not found", dir.c_str(), name.c_str());
    c.x[0] = kNotFound;
}

// Result DeliveryCacheFile::Read(size_t* read, int64_t offset, void*, size_t)
void FileRead(CPU& c) {
    std::pair<std::string, File> f;
    {
        std::lock_guard<std::mutex> l(g_lock);
        const auto it = g_files.find(c.x[0]);
        if (it == g_files.end()) {
            if (c.x[1]) st<uint64_t>(c.x[1], 0);
            c.x[0] = kNotFound;
            return;
        }
        f = it->second;
    }
    std::ifstream in(cache_dir() / f.first / f.second.name, std::ios::binary);
    in.seekg(std::streamoff(c.x[2]));
    in.read(reinterpret_cast<char*>(c.x[3]), std::streamsize(c.x[4]));
    const uint64_t got = in ? c.x[4] : uint64_t(std::max<std::streamsize>(in.gcount(), 0));
    if (c.x[1]) st<uint64_t>(c.x[1], got);
    c.x[0] = 0;
}

// Digest DeliveryCacheFile::GetDigest() const: a 16-byte struct, returned in x0:x1 (AAPCS64).
void GetDigest(CPU& c) {
    uint64_t v[2] = {};
    {
        std::lock_guard<std::mutex> l(g_lock);
        const auto it = g_files.find(c.x[0]);
        if (it != g_files.end()) std::memcpy(v, it->second.second.digest, 16);
    }
    c.x[0] = v[0];
    c.x[1] = v[1];
}

// DeliveryCacheFile::~DeliveryCacheFile()
void FileDestroy(CPU& c) {
    std::lock_guard<std::mutex> l(g_lock);
    g_files.erase(c.x[0]);
}

}  // namespace

NX_HLE("_ZN2nn4bcat10InitializeEv", Initialize);
NX_HLE("_ZN2nn4bcat25MountDeliveryCacheStorageEv", Mount);
NX_HLE("_ZN2nn4bcat27UnmountDeliveryCacheStorageEv", ok);
NX_HLE("_ZN2nn4bcat24RequestSyncDeliveryCacheEPNS0_21DeliveryCacheProgressE", no_internet);
NX_HLE("_ZN2nn4bcat22DeliveryCacheDirectory4OpenERKNS0_13DirectoryNameE", DirectoryOpen);
NX_HLE("_ZN2nn4bcat22DeliveryCacheDirectory4ReadEPiPNS0_27DeliveryCacheDirectoryEntryEi", DirectoryRead);
NX_HLE("_ZN2nn4bcat22DeliveryCacheDirectoryD1Ev", DirectoryDestroy);
NX_HLE("_ZN2nn4bcat17DeliveryCacheFile4OpenERKNS0_13DirectoryNameERKNS0_8FileNameE", FileOpen);
NX_HLE("_ZN2nn4bcat17DeliveryCacheFile4ReadEPmlPvm", FileRead);
NX_HLE("_ZN2nn4bcat17DeliveryCacheFile9GetDigestEv", GetDigest);
NX_HLE("_ZN2nn4bcat17DeliveryCacheFileD1Ev", FileDestroy);

}  // namespace nx
