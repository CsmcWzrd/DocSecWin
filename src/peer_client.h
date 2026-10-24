#pragma once
#include "docsec_http.h"
#include <cstdint>
#include <memory>
namespace docsec {
struct Origin {std::string scheme,host,authority;unsigned short port=0;};
Origin parseOrigin(const std::string& url);
// Fixed-method HTTP/1.1 GET client. No redirects, proxies, or caller-supplied headers.
class PeerResponse {
    struct Impl;
    std::unique_ptr<Impl> impl;
public:
    int status=0;uint64_t length=0;
    std::map<std::string,std::string> headers;
    PeerResponse(const Origin& origin,const std::string& path,const std::string& bearer,const std::string& ifMatch="");
    ~PeerResponse();
    size_t read(char* buffer,size_t capacity);
    std::string text(uint64_t limit);
};
}
