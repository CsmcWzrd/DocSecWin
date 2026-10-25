#include "trigger.h"
#include "pull.h"
#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
namespace docsec {
namespace {
const std::string publicApi="/api/v1/documents";
const std::string internalApi="/api/v1/internal/local/documents";
std::vector<std::string> partsOf(const std::string& value,char separator='/') {
    std::vector<std::string> parts;size_t start=0;
    for(;;){auto end=value.find(separator,start);parts.push_back(value.substr(start,end-start));if(end==std::string::npos)break;start=end+1;}
    return parts;
}
bool validItem(const std::string& key) {
    auto p=partsOf(key);if(p.size()!=1&&p.size()!=3&&p.size()!=5)return false;
    for(size_t i=0;i<p.size();i+=2)if(!identifier(p[i])||p[i]=="_find")return false;
    if(p.size()>=3&&p[1]!="sections"&&p[1]!="notes")return false;
    return p.size()!=5||(p[1]=="sections"&&(p[3]=="data"||p[3]=="notes"));
}
bool validCollection(const std::string& key) {
    if(key.empty())return true;auto p=partsOf(key);
    if(p.size()==2)return identifier(p[0])&&(p[1]=="sections"||p[1]=="notes");
    return p.size()==4&&identifier(p[0])&&p[1]=="sections"&&identifier(p[2])&&(p[3]=="data"||p[3]=="notes");
}
std::string keyFromUrl(const std::string& url) {
    for(const auto& prefix:{publicApi,internalApi})if(url.compare(0,prefix.size()+1,prefix+"/")==0){auto key=url.substr(prefix.size()+1);if(validItem(key))return key;}
    throw HttpError(502,"peer returned an invalid DocSecWin item URL");
}
Request bufferedRequest(const std::string& method,const std::string& target,const std::string& body="") {
    Request out;out.method=method;out.target=target;out.bodyLength=body.size();
    auto data=std::make_shared<std::string>(body);auto position=std::make_shared<size_t>(0);
    out.readBody=[data,position](char* buffer,size_t capacity){size_t n=std::min(capacity,data->size()-*position);std::memcpy(buffer,data->data()+*position,n);*position+=n;return n;};return out;
}
std::string decode(const std::string& value) {
    std::string out;auto hex=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;};
    for(size_t i=0;i<value.size();++i){char c=value[i];if(c=='+')c=' ';else if(c=='%'){if(i+2>=value.size())throw HttpError(400,"invalid query escape");int a=hex(value[++i]),b=hex(value[++i]);if(a<0||b<0)throw HttpError(400,"invalid query escape");c=char(a*16+b);}if(!c)throw HttpError(400,"invalid NUL in query");out+=c;}return out;
}
std::string encode(const std::string& value) {
    const char* hex="0123456789ABCDEF";std::string out;
    for(unsigned char c:value)if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~')out+=char(c);else{out+='%';out+=hex[c>>4];out+=hex[c&15];}return out;
}
void addUrlProjection(Json& body,bool& hideUrl) {
    if(!body.has("fields"))return;auto& fields=body["fields"];
    if(fields.type!=Json::Array||fields.array.size()>64)throw HttpError(400,"fields must be an array of at most 64 names");
    if(fields.array.empty())return;
    const std::set<std::string> known={"id","url","resource_type","title","kind","encoding","content_type","size","revision","archive_id","created_at","updated_at","timestamp","flags","extra","additional","counters","sha256","zar_checksum","tags","attributes"};
    Json selected=Json::arr();std::set<std::string> seen;bool present=false;
    for(const auto& f:fields.array){auto name=f.str();if(name.empty()||name.find('.')!=std::string::npos)throw HttpError(400,"projection fields must be top-level metadata names");
        if(name=="url")present=true;if(known.count(name)&&seen.insert(name).second)selected.array.emplace_back(name);}
    if(!present){selected.array.emplace_back("url");hideUrl=true;}fields=std::move(selected);
}
}
std::optional<std::string> clientRetrievalTarget(const Request& request) {
    const std::string marker="pretend-to-be-client:";std::optional<std::string> result;
    for(const auto& header:{"client-identifier","x-client-identifier","user-agent"}){
        auto i=request.headers.find(header);if(i==request.headers.end())continue;
        const auto& value=i->second;size_t pos=value.find(marker);if(pos==std::string::npos)continue;
        if(result||value.find(marker,pos+marker.size())!=std::string::npos)throw HttpError(400,"multiple pretend-to-be-client markers");
        if(pos&&value[pos-1]!=';'&&value[pos-1]!=' '&&value[pos-1]!='\t')throw HttpError(400,"invalid client identifier marker boundary");
        size_t start=pos+marker.size(),end=value.find_first_of("; \t",start);
        auto target=value.substr(start,end-start);parsePeerTarget(target);result=target;
    }
    return result;
}
Response PullService::trigger(const std::string& user,const Request& request,const std::string& target) {
    auto peer=selectPeer(target);
    auto auth=request.headers.find("x-docsec-source-authorization");
    if(auth==request.headers.end()||auth->second.compare(0,7,"Bearer ")||auth->second.size()==7)throw HttpError(400,"X-DocSec-Source-Authorization: Bearer REMOTE_TOKEN is required");
    std::string sourceToken=auth->second.substr(7);
    if(request.method!="GET"&&request.method!="POST")throw HttpError(405,"client retrieval trigger supports GET or POST collection/_find","GET, POST");
    if(request.method=="GET"&&request.bodyLength)throw HttpError(400,"triggered GET requires an empty body");
    auto question=request.target.find('?');auto path=request.target.substr(0,question);std::string key,localPrefix;
    for(const auto& prefix:{publicApi,internalApi})if(path==prefix||path.compare(0,prefix.size()+1,prefix+"/")==0){localPrefix=prefix;key=path==prefix?"":path.substr(prefix.size()+1);break;}
    if(localPrefix.empty())throw HttpError(400,"client retrieval trigger is restricted to document data routes");
    bool find=false,metadata=false;
    if(key=="_find"){key.clear();find=true;}else if(key.size()>6&&key.substr(key.size()-6)=="/_find"){key.resize(key.size()-6);find=true;}
    if(key.size()>9&&key.substr(key.size()-9)=="/metadata"&&validItem(key.substr(0,key.size()-9))){key.resize(key.size()-9);metadata=true;}
    bool collection=validCollection(key);
    if((!collection&&!validItem(key))||(find&&!collection)||(metadata&&collection))throw HttpError(400,"invalid triggered retrieval path");
    if((find&&request.method!="POST")||(!find&&request.method!="GET"))throw HttpError(405,"POST is only supported for collection/_find",find?"POST":"GET");
    bool hideUrl=false,queryFields=false;std::string remoteQuery,body;
    if(question!=std::string::npos){
        if(!collection)throw HttpError(400,"item query options are unsupported");
        std::set<std::string> names;auto query=request.target.substr(question+1);if(!query.empty()){
            for(const auto& part:partsOf(query,'&')){auto eq=part.find('=');auto name=decode(part.substr(0,eq)),value=eq==std::string::npos?"":decode(part.substr(eq+1));
                if(!names.insert(name).second)throw HttpError(400,"duplicate query parameter");
                if(name=="fields"){queryFields=true;hideUrl=false;Json projection=Json::obj();projection["fields"]=Json::arr();for(const auto& f:partsOf(value,','))projection["fields"].array.emplace_back(f);addUrlProjection(projection,hideUrl);value.clear();for(const auto& f:projection.at("fields").array){if(!value.empty())value+=',';value+=f.str();}}
                if(!remoteQuery.empty())remoteQuery+='&';remoteQuery+=encode(name)+"="+encode(value);
            }
        }
        if(!remoteQuery.empty())remoteQuery="?"+remoteQuery;
    }
    if(find){auto spec=Json::parse(request.readText(256*1024));if(spec.type!=Json::Object)throw HttpError(400,"_find JSON object required");
        // Respect both query and body projections independently, as the remote API does.
        if(!queryFields)addUrlProjection(spec,hideUrl);
        body=spec.dump();}
    std::string remotePath=peer.second.apiPrefix+(key.empty()?"":"/"+key)+(find?"/_find":metadata?"/metadata":"")+remoteQuery;
    auto getLocal=[&](const std::string& itemKey)->std::optional<Json>{
        try{return Json::parse(database.handle(user,bufferedRequest("GET",publicApi+"/"+itemKey+"/metadata")).body);}
        catch(const HttpError& e){if(e.status==404)return {};throw;}
    };
    auto copy=[&](const std::string& itemKey,bool parentOnly){
        auto existing=getLocal(itemKey);if(parentOnly&&existing)return;
        auto source=peer.second.apiPrefix+"/"+itemKey;
        PeerResponse info(peer.second,source+"/metadata",sourceToken);
        if(info.status!=200)throw HttpError(502,"peer metadata retrieval failed with HTTP "+std::to_string(info.status));
        auto meta=Json::parse(info.text(1024*1024));
        if(keyFromUrl(meta.at("url").str())!=itemKey)throw HttpError(502,"peer metadata URL does not match requested item");
        if(existing&&existing->has("attributes")&&existing->at("attributes").has("_docsec_source")){
            const auto& provenance=existing->at("attributes").at("_docsec_source");
            if(provenance.has("peer")&&provenance.has("path")&&provenance.has("revision")&&provenance.has("sha256")&&
               provenance.at("peer").str()==peer.first&&provenance.at("path").str()==source&&
               provenance.at("revision").dump()==meta.at("revision").dump()&&provenance.at("sha256").str()==meta.at("sha256").str()&&
               existing->at("sha256").str()==meta.at("sha256").str()) {return;}
        }
        Json pullBody=Json::obj();pullBody["peer"]=Json(peer.first);pullBody["source_path"]=Json(source);pullBody["destination_path"]=Json(publicApi+"/"+itemKey);pullBody["source_token"]=Json(sourceToken);pullBody["overwrite"]=Json::boolean(true);
        auto receipt=pull(user,bufferedRequest("POST","/api/v1/internal/pull",pullBody.dump()));
        if(receipt.status!=200)throw HttpError(receipt.status,"triggered peer pull failed; earlier committed items remain local");
    };
    auto copyWithParents=[&](const std::string& itemKey){
        auto parts=partsOf(itemKey);if(parts.size()>1)copy(parts[0],true);
        if(parts.size()==5)copy(parts[0]+"/sections/"+parts[2],true);
        copy(itemKey,false);
    };
    if(collection){
        PeerResponse response(peer.second,remotePath,sourceToken,"",find?"POST":"GET",body);
        if(response.status!=200)throw HttpError(response.status==401?502:response.status,"peer query failed with HTTP "+std::to_string(response.status));
        auto list=Json::parse(response.text(8*1024*1024));const auto& items=list.at("items");
        if(items.type!=Json::Array||items.array.size()>1000)throw HttpError(502,"invalid peer query items");
        std::set<std::string> copied;
        for(const auto& item:items.array){auto itemKey=keyFromUrl(item.at("url").str());
            if(!key.empty()&&itemKey.compare(0,key.size()+1,key+"/"))throw HttpError(502,"peer returned item outside requested collection");
            if(copied.insert(itemKey).second)copyWithParents(itemKey);
        }
    }else copyWithParents(key);
    // A trigger gathers information for local processing. Never construct a
    // local GET response here: its stream could disclose the stored payload.
    Response result;result.status=200;return result;
}
}
