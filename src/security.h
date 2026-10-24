#pragma once
#include "docsec_http.h"
#include <chrono>
#include <filesystem>
#include <map>
#include <mutex>
namespace docsec {
namespace fs = std::filesystem;
std::string randomHex(size_t bytes);
std::string digest(const std::string& input);
bool identifier(const std::string& value);
void privateDirectory(const fs::path& path);
void rejectSymlink(const fs::path& path);
void atomicReplace(const fs::path& temp, const fs::path& target);
class RootLock {
#ifdef _WIN32
    void* handle;
#else
    int handle;
#endif
public:
    explicit RootLock(const fs::path& root);
    ~RootLock();
    RootLock(const RootLock&)=delete;
    RootLock& operator=(const RootLock&)=delete;
};
class Security {
    fs::path root;
    struct Session { std::string user; std::chrono::steady_clock::time_point expires; };
    std::map<std::string,Session> sessions;
    std::mutex mutex;
    std::chrono::steady_clock::time_point window = std::chrono::steady_clock::now();
    unsigned attempts=0;
public:
    explicit Security(fs::path p) : root(std::move(p)) {}
    void addUser(const std::string& username,const std::string& password);
    Response login(const Request& r);
    std::string authenticate(const Request& r);
    Response logout(const Request& r);
};
}
