#include "cors.h"
#include "peer_client.h"
#include <fstream>
#include <sstream>
namespace docsec {
namespace {
std::string trim(const std::string& s){auto a=s.find_first_not_of(" \t\r"),b=s.find_last_not_of(" \t\r");return a==std::string::npos?"":s.substr(a,b-a+1);}
std::string lower(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c=char(c-'A'+'a');return s;}
}
CorsPolicy::CorsPolicy(const fs::path& root){
    auto path=root/"cors.conf";rejectSymlink(path);if(!fs::exists(path))return;
    std::ifstream input(path);if(!input)throw std::runtime_error("cannot read cors.conf");std::string line;
    while(std::getline(input,line)){line=trim(line);if(line.empty()||line.front()=='#')continue;
        // Validate exact HTTP(S) origins; retain the wire form used by browsers.
        parseOrigin(line);origins.insert(line);
    }
}
Response CorsPolicy::dispatch(const Request& request,const Handler& handler) const {
    auto origin=request.headers.find("origin");bool allowed=origin!=request.headers.end()&&origins.count(origin->second);
    bool gathering=false;
    for(const auto& name:{"client-identifier","x-client-identifier","user-agent"}){
        auto header=request.headers.find(name);
        if(header!=request.headers.end()&&header->second.find("pretend-to-be-client:")!=std::string::npos)gathering=true;
    }
    auto decorate=[&](Response result){
        // Apply to success, validation/authentication errors and unexpected errors.
        // Keep HTTP control headers, but never transmit payloads or import receipts.
        if(gathering){result.body.clear();result.readStream={};result.streamLength=0;result.advertisedLength=0;}
if(allowed){result.headers["Access-Control-Allow-Origin"]=origin->second;result.headers["Vary"]="Origin";
        result.headers["Access-Control-Expose-Headers"]="ETag, Location, Content-Range, X-Content-SHA256, X-DocSec-Retrieval, X-DocSec-Peer, X-DocSec-Imported-Count, X-DocSec-Unchanged-Count";}return result;};
    try{
        if(request.method=="OPTIONS"&&request.headers.count("access-control-request-method")){
            if(!allowed)throw HttpError(403,"browser origin is not configured in cors.conf");
            const std::set<std::string> methods={"GET","HEAD","POST","PUT","PATCH","DELETE"};
            if(!methods.count(request.headers.at("access-control-request-method")))throw HttpError(403,"browser request method is not allowed");
            const std::set<std::string> headers={"authorization","content-type","client-identifier","x-client-identifier","x-docsec-source-authorization","range","if-match","if-none-match","if-range","x-docsec-id","x-docsec-kind","x-docsec-encoding","x-docsec-title","x-docsec-flags","x-docsec-extra","x-docsec-additional","x-docsec-timestamp","x-docsec-counters"};
            auto requested=request.headers.find("access-control-request-headers");std::string selected;
            if(requested!=request.headers.end()){std::istringstream names(requested->second);std::string name;
                while(std::getline(names,name,',')){name=lower(trim(name));if(!headers.count(name))throw HttpError(403,"browser request header is not allowed");if(!selected.empty())selected+=", ";selected+=name;}}
            Response result;result.status=204;result.headers["Access-Control-Allow-Methods"]="GET, HEAD, POST, PUT, PATCH, DELETE";
            if(!selected.empty())result.headers["Access-Control-Allow-Headers"]=selected;
            result.headers["Access-Control-Max-Age"]="600";result=decorate(result);result.headers["Vary"]="Origin, Access-Control-Request-Method, Access-Control-Request-Headers";return result;
        }
        return decorate(handler(request));
    }catch(const HttpError& e){Response result;result.status=e.status;result.body="{\"error\":"+quote(e.what())+"}";if(e.status==401)result.headers["WWW-Authenticate"]="Bearer realm=\"DocSecWin\"";if(!e.allow.empty())result.headers["Allow"]=e.allow;return decorate(result);}
    catch(const std::exception&){Response result;result.status=500;result.body="{\"error\":\"internal server error\"}";return decorate(result);}
}
}
