// DocSecWin native transport for HttpdWin. No interpreter or CGI backend.
#include "docsec_http.h"
#include "httpresponse.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <deque>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using Socket = SOCKET;
static constexpr Socket badSocket = INVALID_SOCKET;
static void closeSocket(Socket s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
using Socket = int;
static constexpr Socket badSocket = -1;
static void closeSocket(Socket s) { close(s); }
#endif
thread_local int globalThreadId = 0;
std::string sessionIdName = "DocSecWin";
uint64_t sessionMaxAge = 3600;
CookieManager cookieManager;
// The legacy response builder logs only status. Credentials and bodies are never logged.
int httpdloglevel = -1;
void httpdlog(const char*, std::string) {}
void httpdlogHdr(const char*, std::string) {}
namespace docsec {
std::string quote(const std::string& s) {
    const char* hex = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += char(c);
    }
    return out + "\"";
}
static std::string lower(std::string s) {
    for (auto& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
static bool token(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s)
        if (!(std::isalnum(c) || std::string("!#$%&'*+-.^_`|~").find(c) != std::string::npos)) return false;
    return true;
}
static std::string trim(std::string s) {
    auto b = s.find_first_not_of(" \t"), e = s.find_last_not_of(" \t");
    return b == std::string::npos ? "" : s.substr(b, e-b+1);
}
static Request readRequest(Socket sock) {
    constexpr size_t maxHeaders = 16384;
    constexpr uint64_t maxBody = 0x7fffffffffffffffULL - 32768;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    std::string wire;
    auto receive = [&] {
        if (std::chrono::steady_clock::now() > deadline) throw HttpError(408,"request timeout");
        char buffer[4096]; int n = recv(sock, buffer, sizeof buffer, 0);
        if (n <= 0) throw HttpError(400,"incomplete request");
        wire.append(buffer, static_cast<size_t>(n));
    };
    size_t end;
    while ((end = wire.find("\r\n\r\n")) == std::string::npos) {
        if (wire.size() > maxHeaders) throw HttpError(431,"headers too large");
        receive();
    }
    if (end > maxHeaders) throw HttpError(431,"headers too large");
    std::string header = wire.substr(0,end);
    std::istringstream stream(header); std::string line, version, extra;
    std::getline(stream,line); if (!line.empty() && line.back() == '\r') line.pop_back();
    Request r; std::istringstream first(line);
    if (!(first >> r.method >> r.target >> version) || (first >> extra) || version != "HTTP/1.1" || !token(r.method))
        throw HttpError(400,"HTTP/1.1 required");
    if (r.target.empty() || r.target[0] != '/' || r.target.size() > 2048) throw HttpError(400,"invalid target");
    while (std::getline(stream,line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto p = line.find(':');
        if (p == std::string::npos || !token(line.substr(0,p))) throw HttpError(400,"invalid header");
        auto key = lower(line.substr(0,p)), val = trim(line.substr(p+1));
        for (unsigned char c : val) if ((c < 32 && c != '\t') || c == 127) throw HttpError(400,"invalid header value");
        if (!r.headers.emplace(key,val).second) throw HttpError(400,"duplicate header");
    }
    if (!r.headers.count("host") || r.headers.at("host").empty()) throw HttpError(400,"Host required");
    if (r.headers.count("transfer-encoding")) throw HttpError(501,"transfer encoding unsupported; use Content-Length");
    if (r.headers.count("expect") && lower(r.headers.at("expect"))!="100-continue") throw HttpError(417,"unsupported expectation");
    uint64_t length = 0;
    if (r.headers.count("content-length")) {
        const auto& s = r.headers.at("content-length");
        if (s.empty()) throw HttpError(400,"invalid Content-Length");
        for (char c : s) {
            if (c < '0' || c > '9') throw HttpError(400,"invalid Content-Length");
            if (length > (maxBody-uint64_t(c-'0'))/10) throw HttpError(413,"64-bit body size exceeded");
            length = length*10 + size_t(c-'0');
            if (length > maxBody) throw HttpError(413,"body too large");
        }
    } else if (r.method == "PUT" || r.method == "POST" || r.method == "PATCH") throw HttpError(411,"Content-Length required");
    const size_t start = end+4;
    struct Body { std::string pending; size_t pos=0; uint64_t remaining=0; bool expect=false; };
    auto state=std::make_shared<Body>();
    state->pending=wire.substr(start,static_cast<size_t>(std::min<uint64_t>(length,wire.size()-start)));
    state->remaining=length;state->expect=r.headers.count("expect")!=0;
    r.bodyLength=length;
    r.readBody=[sock,state](char* buffer,size_t capacity)->size_t {
        if(!state->remaining)return 0;
        if(state->expect){const char* interim="HTTP/1.1 100 Continue\r\n\r\n";size_t left=25;while(left){int n=send(sock,interim,static_cast<int>(left),0);if(n<=0)throw HttpError(408,"connection closed");interim+=n;left-=size_t(n);}state->expect=false;}
        size_t want=static_cast<size_t>(std::min<uint64_t>(state->remaining,capacity));
        size_t pending=state->pending.size()-state->pos;
        if(pending){size_t n=std::min(want,pending);std::memcpy(buffer,state->pending.data()+state->pos,n);state->pos+=n;state->remaining-=n;return n;}
        int n=recv(sock,buffer,static_cast<int>(std::min<size_t>(want,65536)),0);
        if(n<0)throw HttpError(408,"body receive timeout");if(n==0)throw HttpError(400,"incomplete request body");
        state->remaining-=static_cast<uint64_t>(n);return static_cast<size_t>(n);
    };
    return r;
}
static std::string reason(int code) {
    switch(code) {
    case 304:return "Not Modified"; case 200:return "OK"; case 201:return "Created"; case 204:return "No Content"; case 206:return "Partial Content";
    case 412:return "Precondition Failed"; case 416:return "Range Not Satisfiable"; case 422:return "Unprocessable Content"; case 507:return "Insufficient Storage";
    case 400:return "Bad Request"; case 401:return "Unauthorized"; case 404:return "Not Found";
    case 405:return "Method Not Allowed"; case 408:return "Request Timeout";
    case 409:return "Conflict"; case 411:return "Length Required"; case 413:return "Content Too Large";
    case 415:return "Unsupported Media Type"; case 417:return "Expectation Failed";
    case 429:return "Too Many Requests"; case 431:return "Request Header Fields Too Large";
    case 502:return "Bad Gateway"; case 501:return "Not Implemented"; case 503:return "Service Unavailable";
    default:return "Internal Server Error";
    }
}
static bool sendAll(Socket s, const char* data, size_t length) {
    while (length) {
        int n = send(s,data,static_cast<int>(std::min<size_t>(length,1024*1024)),0);
        if (n <= 0) return false;
        data += n; length -= size_t(n);
    }
    return true;
}
static void respond(Socket sock, Response response, bool head, bool& committed) {
    // HttpdWin's existing response builder; body is sent separately for binary safety.
    auto resp = std::make_unique<HttpResponse>(std::to_string(response.status),reason(response.status),"",response.type);
    static_assert(sizeof(size_t)>=8,"DocSecWin large-file transport requires a 64-bit build");
    resp->m_HttpData.clear(); resp->m_ActualFileSize = response.advertisedLength!=UINT64_MAX ? static_cast<size_t>(response.advertisedLength) : response.readStream ? static_cast<size_t>(response.streamLength) : response.body.size();
    std::map<std::string,std::string> headers = {
        {"Connection: ","close"}, {"Cache-Control: ","no-store"}, {"X-Content-Type-Options: ","nosniff"}};
    for (const auto& h : response.headers) headers[h.first+": "] = h.second;
    resp->BuildResponseHeader(&headers);
    committed=true;
    if(!sendAll(sock,reinterpret_cast<const char*>(resp->m_Buffer),resp->m_ResponseHeaderLen)||head||response.status==304||response.status==204)return;
    if(!response.readStream){sendAll(sock,response.body.data(),response.body.size());return;}
    std::array<char,65536> buffer{};uint64_t remaining=response.streamLength;
    while(remaining){size_t want=static_cast<size_t>(std::min<uint64_t>(remaining,buffer.size()));size_t n=response.readStream(buffer.data(),want);
        if(!n||n>want)throw std::runtime_error("incomplete streamed response");if(!sendAll(sock,buffer.data(),n))return;remaining-=n;}
}
void serve(const std::string& address, unsigned short port, const Handler& handler) {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2),&data)) throw std::runtime_error("WSAStartup failed");
#else
    signal(SIGPIPE,SIG_IGN);
#endif
    Socket listener = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (listener == badSocket) throw std::runtime_error("socket failed");
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET,address.c_str(),&addr.sin_addr) != 1) { closeSocket(listener); throw std::runtime_error("numeric IPv4 bind address required"); }
#ifdef _WIN32
    int exclusive=1;
    setsockopt(listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof exclusive);
#else
    int reuse=1; setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof reuse);
#endif
    if (bind(listener,reinterpret_cast<sockaddr*>(&addr),sizeof addr) || listen(listener,64)) {
        closeSocket(listener); throw std::runtime_error("bind/listen failed");
    }
    struct Shared { std::mutex mutex; std::condition_variable cv; std::deque<Socket> queue; bool done=false; } shared;
    std::vector<std::thread> workers;
    for (int i=0;i<8;++i) workers.emplace_back([&,i] {
        globalThreadId=i;
        for (;;) {
            Socket client;
            { std::unique_lock<std::mutex> lock(shared.mutex);
              shared.cv.wait(lock,[&]{return shared.done || !shared.queue.empty();});
              if (shared.done && shared.queue.empty()) return;
              client=shared.queue.front(); shared.queue.pop_front(); }
#ifdef _WIN32
            DWORD timeout=30000;
#else
            timeval timeout{30,0};
#endif
            setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof timeout);
            setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof timeout);
            bool committed=false,head=false;
            try { auto r=readRequest(client);head=r.method=="HEAD";respond(client,handler(r),head,committed); }
            catch(const HttpError& e) { if(!committed){Response r;r.status=e.status;r.body="{\"error\":"+quote(e.what())+"}";if(e.status==401)r.headers["WWW-Authenticate"]="Bearer realm=\"DocSecWin\"";if(!e.allow.empty())r.headers["Allow"]=e.allow;respond(client,r,head,committed);} }
            catch(const std::exception&) { if(!committed){Response r;r.status=500;r.body="{\"error\":\"internal server error\"}";respond(client,r,head,committed);} }
            closeSocket(client);
        }
    });
    for (;;) {
        Socket client=accept(listener,nullptr,nullptr);
        if(client==badSocket) break;
        { std::lock_guard<std::mutex> lock(shared.mutex);
          if(shared.queue.size()>=64) { closeSocket(client); continue; }
          shared.queue.push_back(client); }
        shared.cv.notify_one();
    }
    {std::lock_guard<std::mutex> lock(shared.mutex); shared.done=true;}
    shared.cv.notify_all(); for(auto& worker:workers) worker.join(); closeSocket(listener);
}
}
