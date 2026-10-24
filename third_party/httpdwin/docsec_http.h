#pragma once
#include <functional>
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
namespace docsec {
struct HttpError : std::runtime_error {
    int status;
    std::string allow;
    HttpError(int code, const std::string& message, std::string allowed = "")
        : std::runtime_error(message), status(code), allow(std::move(allowed)) {}
};
struct Request {
    std::string method, target;
    std::string internalMetadata; // In-process import only; never parsed from HTTP headers.
    uint64_t bodyLength=0;
    std::map<std::string,std::string> headers;
    std::function<size_t(char*,size_t)> readBody;
    std::string readText(uint64_t limit) const {
        if(bodyLength>limit) throw HttpError(413,"metadata body too large");
        std::string result;std::array<char,65536> buffer{};uint64_t remaining=bodyLength;
        while(remaining){size_t want=static_cast<size_t>(remaining<buffer.size()?remaining:buffer.size());size_t n=readBody?readBody(buffer.data(),want):0;
            if(!n||n>want)throw HttpError(400,"incomplete request body");result.append(buffer.data(),n);remaining-=n;}
        return result;
    }
};
struct Response {
    int status = 200;
    std::string body, type = "application/json";
    std::map<std::string,std::string> headers;
    uint64_t streamLength=0;
    uint64_t advertisedLength=UINT64_MAX;
    std::function<size_t(char*,size_t)> readStream;
};
using Handler = std::function<Response(const Request&)>;
// HTTP/1.1 with explicit Connection: close, bounded framing and fixed worker pool.
void serve(const std::string& address, unsigned short port, const Handler& handler);
std::string quote(const std::string& value);
}
