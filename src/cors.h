#pragma once
#include "security.h"
#include <set>
namespace docsec {
class CorsPolicy {
    std::set<std::string> origins;
public:
    explicit CorsPolicy(const fs::path& root);
    Response dispatch(const Request& request,const Handler& handler) const;
};
}
