#pragma once
#include "docsec_http.h"
#include <cstdint>
#include <memory>
namespace docsec {
struct Origin {std::string scheme,host,authority;unsigned short port=0;std::string apiPrefix="/api/v1/documents";};
Origin parseOrigin(const std::string& url);
struct PeerTarget {std::string host;unsigned short port=0;bool explicitPort=false;};
PeerTarget parsePeerTarget(const std::string& target);
std::string canonicalPeerHost(const std::string& host);
// HTTP/1.1 GET / bounded POST _find client. No redirects or forwarded trigger headers.
class PeerResponse {
    struct Impl;
    std::unique_ptr<Impl> impl;
public:
    int status=0;uint64_t length=0;
    std::map<std::string,std::string> headers;
    PeerResponse(const Origin& origin,const std::string& path,const std::string& bearer,const std::string& ifMatch="",const std::string& method="GET",const std::string& body="");
    ~PeerResponse();
    size_t read(char* buffer,size_t capacity);
    std::string text(uint64_t limit);
};
}
