#pragma once
#include "security.h"
#include "json.h"
namespace docsec {
class Database {
    fs::path root;
    std::mutex mutex;
    struct Entity { Json meta=Json::obj(); std::string blob,legacy; bool legacyData=false; };
    using Entities=std::map<std::string,Entity>;
    Entities load(const fs::path& path);
    void save(const fs::path& path,Entities& entities);
    void storePayload(const fs::path& dir,const std::string& key,Entity& entity,uint64_t length,const std::function<size_t(char*,size_t)>& source);
public:
    explicit Database(fs::path p):root(std::move(p)){}
    void initialize(const std::string& user);
    uint64_t collectGarbage(const std::string& user);
    Response handle(const std::string& user,const Request& request);
};
}
