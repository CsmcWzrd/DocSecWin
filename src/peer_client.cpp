#include "peer_client.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using PeerSocket=SOCKET;
static constexpr PeerSocket invalidPeer=INVALID_SOCKET;
static void closePeer(PeerSocket s){closesocket(s);}
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
using PeerSocket=int;
static constexpr PeerSocket invalidPeer=-1;
static void closePeer(PeerSocket s){close(s);}
#endif
namespace docsec {
namespace {
unsigned short parsePort(const std::string& value){
    if(value.empty()||value.size()>5)throw HttpError(400,"invalid peer port");
    unsigned port=0;for(char c:value){if(c<'0'||c>'9')throw HttpError(400,"invalid peer port");port=port*10+unsigned(c-'0');}
    if(!port||port>65535)throw HttpError(400,"invalid peer port");return static_cast<unsigned short>(port);
}
}
std::string canonicalPeerHost(const std::string& host){
    if(host.empty()||host.size()>253)throw HttpError(400,"invalid peer hostname or IP address");
    in_addr ip4{};in6_addr ip6{};char text[INET6_ADDRSTRLEN]{};
    if(inet_pton(AF_INET,host.c_str(),&ip4)==1){if(!inet_ntop(AF_INET,&ip4,text,sizeof text))throw HttpError(400,"invalid IPv4 address");return text;}
    if(inet_pton(AF_INET6,host.c_str(),&ip6)==1){if(!inet_ntop(AF_INET6,&ip6,text,sizeof text))throw HttpError(400,"invalid IPv6 address");return text;}
    std::string value=host;for(auto& c:value)if(c>='A'&&c<='Z')c=char(c-'A'+'a');
    if(value.back()=='.')value.pop_back();if(value.empty())throw HttpError(400,"invalid peer hostname");
    size_t start=0;bool onlyDigits=true;
    for(size_t i=0;i<=value.size();++i){if(i==value.size()||value[i]=='.'){auto n=i-start;if(!n||n>63||value[start]=='-'||value[i-1]=='-')throw HttpError(400,"invalid peer hostname");start=i+1;continue;}
        char c=value[i];if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'))throw HttpError(400,"invalid peer hostname or IP address");if(c<'0'||c>'9')onlyDigits=false;}
    if(onlyDigits)throw HttpError(400,"invalid numeric IP address");return value;
}
PeerTarget parsePeerTarget(const std::string& target){
    if(target.empty()||target.find_first_of("/@?#\\% \t\r\n")!=std::string::npos)throw HttpError(400,"trigger target must be a hostname or IP, optionally with a port");
    PeerTarget out;std::string host;
    if(target.front()=='['){auto close=target.find(']');if(close==std::string::npos)throw HttpError(400,"unterminated IPv6 target");host=target.substr(1,close-1);in6_addr ip{};if(inet_pton(AF_INET6,host.c_str(),&ip)!=1)throw HttpError(400,"brackets require an IPv6 address");
        if(close+1<target.size()){if(target[close+1]!=':')throw HttpError(400,"invalid IPv6 target suffix");out.port=parsePort(target.substr(close+2));out.explicitPort=true;}}
    else {auto first=target.find(':'),last=target.rfind(':');if(first!=std::string::npos&&first==last){host=target.substr(0,first);out.port=parsePort(target.substr(first+1));out.explicitPort=true;}else host=target;}
    out.host=canonicalPeerHost(host);return out;
}
Origin parseOrigin(const std::string& url){
    Origin o;auto p=url.find("://");if(p==std::string::npos)throw std::runtime_error("peer origin needs http:// or https://");o.scheme=url.substr(0,p);
    if(o.scheme!="http"&&o.scheme!="https")throw std::runtime_error("unsupported peer scheme");
    o.authority=url.substr(p+3);auto target=parsePeerTarget(o.authority);
    if(o.authority.find(':')!=std::string::npos&&o.authority.front()!='['&&o.authority.find(':')!=o.authority.rfind(':'))throw std::runtime_error("IPv6 URL origins require brackets");
    o.host=target.host;o.port=target.explicitPort?target.port:static_cast<unsigned short>(o.scheme=="https"?443:80);
    o.authority=(o.host.find(':')==std::string::npos?o.host:"["+o.host+"]")+":"+std::to_string(o.port);return o;
}
struct PeerResponse::Impl {
    PeerSocket socket=invalidPeer;SSL_CTX* context=nullptr;SSL* ssl=nullptr;
    std::string pending;size_t cursor=0;uint64_t remaining=0;
    ~Impl(){if(ssl)SSL_free(ssl);if(context)SSL_CTX_free(context);if(socket!=invalidPeer)closePeer(socket);}
    int receive(char* p,int n){int got=ssl?SSL_read(ssl,p,n):recv(socket,p,n,0);if(got<=0)throw HttpError(502,"peer connection ended before response completed");return got;}
    void send(const std::string& s){size_t p=0;while(p<s.size()){int want=static_cast<int>(std::min<size_t>(s.size()-p,65536));int n=ssl?SSL_write(ssl,s.data()+p,want) : ::send(socket,s.data()+p,want,0);if(n<=0)throw HttpError(502,"peer request send failed");p+=static_cast<size_t>(n);}}
};
PeerResponse::PeerResponse(const Origin& origin,const std::string& path,const std::string& token,const std::string& ifMatch,const std::string& method,const std::string& body):impl(std::make_unique<Impl>()){
    if(path.empty()||path[0]!='/'||path.size()>2048||path.find_first_of("\r\n ")!=std::string::npos)throw HttpError(400,"invalid peer path");
    if(method!="GET"&&method!="POST")throw HttpError(400,"unsupported peer request method");
    auto methodPath=path.substr(0,path.find('?'));
    if(method=="POST"&&(body.size()>256*1024||methodPath.size()<6||methodPath.substr(methodPath.size()-6)!="/_find"))throw HttpError(400,"peer POST is restricted to bounded _find queries");
    if(token.empty()||token.size()>4096)throw HttpError(400,"peer token required");for(unsigned char c:token)if(c<33||c>126)throw HttpError(400,"invalid peer token");for(char c:ifMatch)if(c=='\r'||c=='\n')throw HttpError(502,"invalid peer ETag");
#ifdef _WIN32
    struct Runtime { bool ready=false;Runtime(){WSADATA data;ready=WSAStartup(MAKEWORD(2,2),&data)==0;}~Runtime(){if(ready)WSACleanup();} };
    static Runtime runtime;if(!runtime.ready)throw HttpError(502,"peer networking unavailable");
#endif
    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;addrinfo* result=nullptr;
    if(getaddrinfo(origin.host.c_str(),std::to_string(origin.port).c_str(),&hints,&result))throw HttpError(502,"peer DNS resolution failed");
    std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> addresses(result,freeaddrinfo);
    for(auto address=result;address;address=address->ai_next){auto sock=::socket(address->ai_family,address->ai_socktype,address->ai_protocol);if(sock==invalidPeer)continue;
#ifdef _WIN32
        u_long nonblocking=1;ioctlsocket(sock,FIONBIO,&nonblocking);
#else
        int flags=fcntl(sock,F_GETFL,0);fcntl(sock,F_SETFL,flags|O_NONBLOCK);
#endif
        int connected=connect(sock,address->ai_addr,static_cast<int>(address->ai_addrlen));
        if(connected){fd_set writable;FD_ZERO(&writable);FD_SET(sock,&writable);timeval wait{30,0};int ready=select(static_cast<int>(sock)+1,nullptr,&writable,nullptr,&wait);int error=1;
#ifdef _WIN32
            int len=sizeof error;
#else
            socklen_t len=sizeof error;
#endif
            if(ready>0&&getsockopt(sock,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&len)==0&&error==0)connected=0;
        }
        if(connected){closePeer(sock);continue;}
#ifdef _WIN32
        nonblocking=0;ioctlsocket(sock,FIONBIO,&nonblocking);DWORD timeout=30000;
#else
        fcntl(sock,F_SETFL,flags);timeval timeout{30,0};
#endif
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof timeout);setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof timeout);impl->socket=sock;break;
    }
    if(impl->socket==invalidPeer)throw HttpError(502,"cannot connect to configured peer");
    if(origin.scheme=="https"){
        impl->context=SSL_CTX_new(TLS_client_method());if(!impl->context)throw HttpError(502,"peer TLS initialization failed");SSL_CTX_set_verify(impl->context,SSL_VERIFY_PEER,nullptr);
        if(!SSL_CTX_set_min_proto_version(impl->context,TLS1_2_VERSION)||!SSL_CTX_set_default_verify_paths(impl->context))throw HttpError(502,"peer TLS trust store unavailable");
        impl->ssl=SSL_new(impl->context);if(!impl->ssl)throw HttpError(502,"peer TLS allocation failed");
        in_addr ip{};in6_addr ip6{};bool numeric=inet_pton(AF_INET,origin.host.c_str(),&ip)==1||inet_pton(AF_INET6,origin.host.c_str(),&ip6)==1;int verified=numeric?X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(impl->ssl),origin.host.c_str()):SSL_set1_host(impl->ssl,origin.host.c_str());
        if(!verified||(!numeric&&!SSL_set_tlsext_host_name(impl->ssl,origin.host.c_str()))||!SSL_set_fd(impl->ssl,static_cast<int>(impl->socket))||SSL_connect(impl->ssl)!=1||SSL_get_verify_result(impl->ssl)!=X509_V_OK)throw HttpError(502,"peer TLS certificate or handshake failed");
    }
    std::string request=method+" "+path+" HTTP/1.1\r\nHost: "+origin.authority+"\r\nAuthorization: Bearer "+token+"\r\nConnection: close\r\nAccept-Encoding: identity\r\nUser-Agent: DocSecWin/0.3.0\r\n";if(!ifMatch.empty())request+="If-Match: "+ifMatch+"\r\n";if(method=="POST")request+="Content-Type: application/json\r\nContent-Length: "+std::to_string(body.size())+"\r\n";impl->send(request+"\r\n"+body);
    std::string wire;size_t end;std::array<char,4096> buffer{};
    while((end=wire.find("\r\n\r\n"))==std::string::npos){if(wire.size()>65536)throw HttpError(502,"peer response headers too large");wire.append(buffer.data(),static_cast<size_t>(impl->receive(buffer.data(),buffer.size())));}
    if(end>65536)throw HttpError(502,"peer response headers too large");std::istringstream stream(wire.substr(0,end));std::string line,version;std::getline(stream,line);std::istringstream statusLine(line);statusLine>>version>>status;if(version!="HTTP/1.1"||status<200||status>599)throw HttpError(502,"invalid peer HTTP status");
    while(std::getline(stream,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();auto colon=line.find(':');if(colon==std::string::npos||!colon)throw HttpError(502,"invalid peer response header");auto name=line.substr(0,colon),value=line.substr(colon+1);for(auto& c:name)if(c>='A'&&c<='Z')c=char(c-'A'+'a');auto b=value.find_first_not_of(" \t"),e=value.find_last_not_of(" \t");value=b==std::string::npos?"":value.substr(b,e-b+1);for(unsigned char c:value)if(c<32||c==127)throw HttpError(502,"invalid peer response header value");if(!headers.emplace(name,value).second)throw HttpError(502,"duplicate peer response header");}
    if(headers.count("transfer-encoding")||(headers.count("content-encoding")&&headers.at("content-encoding")!="identity"))throw HttpError(502,"peer must send identity Content-Length responses");
    if(!headers.count("content-length"))throw HttpError(502,"peer Content-Length required");auto s=headers.at("content-length");if(s.empty())throw HttpError(502,"invalid peer Content-Length");for(char c:s){if(c<'0'||c>'9'||length>(uint64_t(INT64_MAX)-32768-uint64_t(c-'0'))/10)throw HttpError(502,"invalid peer Content-Length");length=length*10+uint64_t(c-'0');}
    impl->remaining=length;impl->pending=wire.substr(end+4,static_cast<size_t>(std::min<uint64_t>(length,wire.size()-end-4)));
}
PeerResponse::~PeerResponse()=default;
size_t PeerResponse::read(char* out,size_t capacity){if(!impl->remaining)return 0;size_t want=static_cast<size_t>(std::min<uint64_t>(impl->remaining,capacity));size_t buffered=impl->pending.size()-impl->cursor;
    if(buffered){size_t n=std::min(buffered,want);std::memcpy(out,impl->pending.data()+impl->cursor,n);impl->cursor+=n;impl->remaining-=n;return n;}int n=impl->receive(out,static_cast<int>(std::min<size_t>(want,65536)));impl->remaining-=static_cast<uint64_t>(n);return static_cast<size_t>(n);}
std::string PeerResponse::text(uint64_t limit){if(length>limit)throw HttpError(502,"peer metadata response exceeds limit");std::string result;std::array<char,65536> buffer{};while(auto n=read(buffer.data(),buffer.size()))result.append(buffer.data(),n);return result;}
}
