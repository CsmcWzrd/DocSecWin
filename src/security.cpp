#include "security.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace docsec {
static std::string hex(const unsigned char* p,size_t size) {
    const char* digits="0123456789abcdef"; std::string s;
    for(size_t i=0;i<size;++i) {s+=digits[p[i]>>4];s+=digits[p[i]&15];} return s;
}
std::string randomHex(size_t bytes) {
    std::vector<unsigned char> v(bytes);
    if(RAND_bytes(v.data(),static_cast<int>(v.size()))!=1) throw std::runtime_error("secure random failed");
    return hex(v.data(),v.size());
}
std::string digest(const std::string& input) {
    unsigned char out[SHA256_DIGEST_LENGTH]; SHA256(reinterpret_cast<const unsigned char*>(input.data()),input.size(),out);
    return hex(out,sizeof out);
}
bool identifier(const std::string& s) {
    if(s.empty() || s.size()>64) return false;
    for(char c:s) if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-')) return false;
    return true;
}
void rejectSymlink(const fs::path& p) {
    // Trusted administrator chooses root; reject symlinks in every existing component.
    fs::path component;
    for(const auto& part:fs::absolute(p)) {
        component/=part;
        if(fs::is_symlink(fs::symlink_status(component))) throw std::runtime_error("symlink storage paths forbidden");
    }
}
void privateDirectory(const fs::path& p) {
    rejectSymlink(p); fs::create_directories(p);
#ifndef _WIN32
    if(chmod(p.c_str(),0700)) throw std::runtime_error("cannot secure directory");
#endif
}
RootLock::RootLock(const fs::path& root) {
    privateDirectory(root); auto lock=root/"server.lock"; rejectSymlink(lock);
#ifdef _WIN32
    handle=CreateFileW(lock.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(handle==INVALID_HANDLE_VALUE) throw std::runtime_error("storage root already locked");
#else
    handle=open(lock.c_str(),O_CREAT|O_RDWR|O_NOFOLLOW,0600);
    if(handle<0) throw std::runtime_error("cannot open storage lock");
    if(flock(handle,LOCK_EX|LOCK_NB)) {close(handle);throw std::runtime_error("storage root already locked");}
#endif
}
RootLock::~RootLock() {
#ifdef _WIN32
    CloseHandle(handle);
#else
    close(handle);
#endif
}
void atomicReplace(const fs::path& temp,const fs::path& target) {
    rejectSymlink(target); rejectSymlink(temp);
#ifdef _WIN32
    HANDLE file=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open replacement for flush");
    bool ok=FlushFileBuffers(file)!=0; CloseHandle(file);
    if(!ok || !MoveFileExW(temp.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("atomic replacement failed");
#else
    int fd=open(temp.c_str(),O_RDONLY|O_NOFOLLOW);
    if(fd<0) throw std::runtime_error("cannot open replacement for flush");
    int result=fsync(fd); close(fd);
    if(result || rename(temp.c_str(),target.c_str())) throw std::runtime_error("atomic replacement failed");
    fd=open(target.parent_path().c_str(),O_RDONLY|O_DIRECTORY);
    if(fd>=0) {fsync(fd);close(fd);}
#endif
}
static std::string passwordHash(const std::string& password,const std::string& salt) {
    unsigned char key[32];
    if(PKCS5_PBKDF2_HMAC(password.data(),static_cast<int>(password.size()),reinterpret_cast<const unsigned char*>(salt.data()),static_cast<int>(salt.size()),600000,EVP_sha256(),sizeof key,key)!=1)
        throw std::runtime_error("password hashing failed");
    return hex(key,sizeof key);
}
void Security::addUser(const std::string& username,const std::string& password) {
    if(!identifier(username)) throw std::runtime_error("username must be 1-64 ASCII letters, digits, hyphen or underscore");
    if(password.size()<12 || password.size()>1024) throw std::runtime_error("password must be 12-1024 bytes");
    privateDirectory(root/"users"); auto dir=root/"users"/digest(username); privateDirectory(dir);
    auto account=dir/"account"; rejectSymlink(account);
    if(fs::exists(account)) throw std::runtime_error("user already exists");
    auto salt=randomHex(16); auto tmp=dir/("account-"+randomHex(8)+".tmp");
    std::ofstream out(tmp,std::ios::binary); out<<username<<'\n'<<salt<<'\n'<<passwordHash(password,salt)<<'\n';
    out.close(); if(!out) throw std::runtime_error("account write failed"); atomicReplace(tmp,account);
}
static std::string decodeBasic(const std::string& value) {
    if(value.size()<6 || value.substr(0,6)!="Basic ") throw HttpError(401,"Basic credentials required for login");
    std::string b64=value.substr(6);
    if(b64.empty() || b64.size()>2048 || b64.size()%4) throw HttpError(401,"invalid credentials");
    for(char c:b64) if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) throw HttpError(401,"invalid credentials");
    std::vector<unsigned char> decoded(b64.size());
    int n=EVP_DecodeBlock(decoded.data(),reinterpret_cast<const unsigned char*>(b64.data()),static_cast<int>(b64.size()));
    if(n<0) throw HttpError(401,"invalid credentials");
    if(b64.back()=='=') --n;
    if(b64.size()>1 && b64[b64.size()-2]=='=') --n;
    if(n<0) throw HttpError(401,"invalid credentials");
    std::string result(reinterpret_cast<char*>(decoded.data()),static_cast<size_t>(n));
    std::string encoded(4*((result.size()+2)/3),'\0');
    if(!result.empty()) EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&encoded[0]),reinterpret_cast<const unsigned char*>(result.data()),static_cast<int>(result.size()));
    if(encoded!=b64) throw HttpError(401,"invalid credentials");
    return result;
}
Response Security::login(const Request& r) {
    if(r.bodyLength) throw HttpError(400,"login uses Basic authorization and an empty body");
    std::lock_guard<std::mutex> guard(mutex);
    auto now=std::chrono::steady_clock::now();
    if(now-window>std::chrono::minutes(1)) {attempts=0;window=now;}
    if(++attempts>60) throw HttpError(429,"login rate exceeded; retry after one minute");
    auto it=r.headers.find("authorization"); if(it==r.headers.end()) throw HttpError(401,"credentials required");
    auto credentials=decodeBasic(it->second); auto pos=credentials.find(':');
    if(pos==std::string::npos) throw HttpError(401,"invalid credentials");
    auto user=credentials.substr(0,pos), password=credentials.substr(pos+1);
    if(!identifier(user) || password.size()>1024) throw HttpError(401,"invalid credentials");
    auto file=root/"users"/digest(user)/"account"; rejectSymlink(file);
    std::ifstream in(file,std::ios::binary); std::string stored,salt,key;
    std::getline(in,stored);std::getline(in,salt);std::getline(in,key);
    bool valid=bool(in) && stored==user && salt.size()==32 && key.size()==64;
    auto candidate=passwordHash(password,valid?salt:std::string(32,'0'));
    if(!valid || CRYPTO_memcmp(candidate.data(),key.data(),64)) throw HttpError(401,"invalid credentials");
    for(auto i=sessions.begin();i!=sessions.end();) if(i->second.expires<=now) i=sessions.erase(i); else ++i;
    if(sessions.size()>=4096) throw HttpError(503,"session capacity reached");
    auto token=randomHex(32);sessions[digest(token)]={user,now+std::chrono::hours(1)};
    Response result; result.body="{\"token\":"+quote(token)+",\"token_type\":\"Bearer\",\"expires_in\":3600}"; return result;
}
static std::string bearer(const Request& r) {
    auto i=r.headers.find("authorization");
    if(i==r.headers.end() || i->second.substr(0,7)!="Bearer " || i->second.size()!=71) throw HttpError(401,"Bearer token required");
    return i->second.substr(7);
}
std::string Security::authenticate(const Request& r) {
    std::lock_guard<std::mutex> guard(mutex); auto i=sessions.find(digest(bearer(r)));
    if(i==sessions.end() || i->second.expires<=std::chrono::steady_clock::now()) throw HttpError(401,"invalid or expired session");
    return i->second.user;
}
Response Security::logout(const Request& r) {
    std::lock_guard<std::mutex> guard(mutex); sessions.erase(digest(bearer(r))); Response response;response.status=204;return response;
}
}
