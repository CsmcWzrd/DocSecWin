#include "pull.h"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
namespace docsec {
namespace {
const std::string api="/api/v1/documents",internal="/api/v1/internal/local/documents";
std::string keyOf(const std::string& path){
    std::string key;if(path.compare(0,api.size()+1,api+"/")==0)key=path.substr(api.size()+1);else if(path.compare(0,internal.size()+1,internal+"/")==0)key=path.substr(internal.size()+1);else throw HttpError(400,"source/destination must name a DocSecWin item");
    std::vector<std::string> parts;std::istringstream stream(key);std::string part;while(std::getline(stream,part,'/'))parts.push_back(part);
    if(key.empty()||key.back()=='/'||(parts.size()!=1&&parts.size()!=3&&parts.size()!=5))throw HttpError(400,"invalid DocSecWin item path");
    for(size_t i=0;i<parts.size();++i)if(i%2==0){if(!identifier(parts[i])||parts[i]=="_find")throw HttpError(400,"invalid DocSecWin item identifier");}
    if(parts.size()>=3&&parts[1]!="sections"&&parts[1]!="notes")throw HttpError(400,"invalid DocSecWin hierarchy");
    if(parts.size()==5&&(parts[1]!="sections"||(parts[3]!="data"&&parts[3]!="notes")))throw HttpError(400,"invalid DocSecWin hierarchy");return key;
}
Json getJson(const Origin& peer,const std::string& token,const std::string& path){PeerResponse response(peer,path,token);if(response.status!=200)throw HttpError(502,"peer metadata request failed with HTTP "+std::to_string(response.status));try{return Json::parse(response.text(8*1024*1024));}catch(const HttpError&){throw HttpError(502,"invalid peer JSON metadata");}}
Request localRequest(const std::string& method,const std::string& path,const std::string& body){Request r;r.method=method;r.target=path;r.bodyLength=body.size();auto text=std::make_shared<std::string>(body);auto pos=std::make_shared<size_t>(0);r.readBody=[text,pos](char* p,size_t n){n=std::min(n,text->size()-*pos);std::memcpy(p,text->data()+*pos,n);*pos+=n;return n;};return r;}
std::string sourceBase(const std::string& source){return source.compare(0,internal.size()+1,internal+"/")==0?internal:api;}
}
PullService::PullService(Database& db,const fs::path& root):database(db){auto path=root/"peers.conf";rejectSymlink(path);if(!fs::exists(path))return;std::ifstream in(path);if(!in)throw std::runtime_error("cannot read peers.conf");std::string line;while(std::getline(in,line)){if(line.empty()||line[0]=='#')continue;std::istringstream fields(line);std::string name,url,extra;if(!(fields>>name>>url)||(fields>>extra)||!identifier(name))throw std::runtime_error("invalid peers.conf entry; expected NAME ORIGIN");if(!peers.emplace(name,parseOrigin(url)).second)throw std::runtime_error("duplicate peer name");}}
Response PullService::listPeers() const {Json result=Json::obj();result["peers"]=Json::arr();for(const auto& p:peers){Json item=Json::obj();item["name"]=Json(p.first);item["origin"]=Json(p.second.scheme+"://"+p.second.authority);result["peers"].array.push_back(item);}Response r;r.body=result.dump();return r;}
Response PullService::pull(const std::string& user,const Request& request){
    auto input=Json::parse(request.readText(64*1024));if(input.type!=Json::Object)throw HttpError(400,"pull JSON object required");
    for(const auto& x:input.object)if(x.first!="peer"&&x.first!="source_path"&&x.first!="destination_path"&&x.first!="source_token"&&x.first!="recursive"&&x.first!="overwrite")throw HttpError(400,"unsupported pull option: "+x.first);
    auto name=input.at("peer").str(),source=input.at("source_path").str(),token=input.at("source_token").str();auto configured=peers.find(name);if(configured==peers.end())throw HttpError(400,"peer is not configured by the administrator");
    auto key=keyOf(source),destination=input.has("destination_path")?keyOf(input.at("destination_path").str()):key;
    auto shape=[](const std::string& s){std::string out;std::istringstream stream(s);std::string p;unsigned i=0;while(std::getline(stream,p,'/')){if(i++%2)out+="/"+p;else out+="/#";}return out;};
    if(shape(key)!=shape(destination))throw HttpError(400,"source and destination must have the same hierarchy shape");
    bool recursive=false,overwrite=false;
    for(const auto& option:{"recursive","overwrite"})if(input.has(option)){if(input.at(option).type!=Json::Bool)throw HttpError(400,"pull booleans must be true or false");if(std::string(option)=="recursive")recursive=input.at(option).text=="true";else overwrite=input.at(option).text=="true";}
    Json result=Json::obj();result["peer"]=Json(name);result["source_path"]=Json(source);result["destination_path"]=Json(api+"/"+destination);result["imported"]=Json::arr();result["complete"]=Json::boolean(false);
    try{
        auto rootMeta=getJson(configured->second,token,source+"/metadata");std::map<std::string,Json> records;records.emplace(key,rootMeta);
        auto remoteBase=sourceBase(source);
        auto listing=[&](const std::string& collection,bool descend){
            uint64_t offset=0;std::string snapshot;for(;;){std::string query="?limit=100&offset="+std::to_string(offset);if(descend)query+="&recursive=true";if(!snapshot.empty())query+="&snapshot="+snapshot;auto list=getJson(configured->second,token,collection+query);
                if(list.at("items").type!=Json::Array)throw HttpError(502,"peer listing has no items array");auto returned=list.at("items").array.size();
                if(list.has("snapshot")){auto current=list.at("snapshot").str();if(current.size()!=64)throw HttpError(502,"invalid peer snapshot");if(!snapshot.empty()&&snapshot!=current)throw HttpError(502,"peer catalog changed during enumeration");snapshot=current;}
                for(const auto& meta:list.at("items").array){auto itemKey=keyOf(meta.at("url").str());if(itemKey.compare(0,key.size()+1,key+"/"))throw HttpError(502,"peer returned an item outside the requested subtree");records[itemKey]=meta;if(records.size()>10000)throw HttpError(413,"pull subtree exceeds catalog limit");}
                if(!list.has("next_offset")||list.at("next_offset").type==Json::Null)break;auto next=list.at("next_offset").integer();if(!returned||next<=offset)throw HttpError(502,"invalid peer pagination");offset=next;
            }
        };
        if(recursive){auto type=rootMeta.at("resource_type").str();if(type=="document"){listing(source+"/notes",false);listing(source+"/sections",true);}else if(type=="section"){listing(source+"/notes",false);listing(source+"/data",false);}}
        for(const auto& entry:records){auto sourceItem=remoteBase+"/"+entry.first;auto localKey=destination+entry.first.substr(key.size());auto localPath=api+"/"+localKey;
            // Refresh the per-item metadata and require its ETag during the content GET.
            PeerResponse metadataResponse(configured->second,sourceItem+"/metadata",token);if(metadataResponse.status!=200)throw HttpError(502,"peer item metadata failed with HTTP "+std::to_string(metadataResponse.status));
            auto meta=Json::parse(metadataResponse.text(1024*1024));if(!metadataResponse.headers.count("etag"))throw HttpError(502,"peer metadata ETag required");auto sourceEtag=metadataResponse.headers.at("etag");
            Json patch=Json::obj();for(const auto& field:{"title","content_type","kind","encoding","flags","timestamp","extra","additional","counters","tags","attributes"})patch[field]=meta.at(field);
            Json provenance=Json::obj();provenance["peer"]=Json(name);provenance["path"]=Json(sourceItem);provenance["revision"]=meta.at("revision");provenance["sha256"]=meta.at("sha256");provenance["source_created_at"]=meta.at("created_at");provenance["source_updated_at"]=meta.at("updated_at");patch["attributes"]["_docsec_source"]=provenance;
            auto resourceType=meta.at("resource_type").str();bool content=resourceType=="data"||resourceType=="note";Response stored;
            if(content){
                PeerResponse payload(configured->second,sourceItem,token,sourceEtag);if(payload.status!=200)throw HttpError(502,"peer content request failed with HTTP "+std::to_string(payload.status));if(payload.length!=meta.at("size").integer())throw HttpError(502,"peer content length changed");
                auto expected=meta.at("sha256").str();if(expected.size()!=64)throw HttpError(502,"peer content SHA256 required");
                std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(),EVP_MD_CTX_free);if(!hash||EVP_DigestInit_ex(hash.get(),EVP_sha256(),nullptr)!=1)throw std::runtime_error("pull hash init failed");uint64_t remaining=payload.length;
                auto finish=[&]{uint8_t digest[32];unsigned length=0;if(EVP_DigestFinal_ex(hash.get(),digest,&length)!=1||length!=32)throw std::runtime_error("pull hash failed");static const char* hex="0123456789abcdef";std::string actual;for(auto b:digest){actual+=hex[b>>4];actual+=hex[b&15];}if(actual!=expected)throw HttpError(502,"peer content checksum mismatch");};
                if(!remaining)finish();Request local;local.method="PUT";local.target=localPath;local.bodyLength=payload.length;local.internalMetadata=patch.dump();local.headers["content-type"]=meta.at("content_type").str();if(!overwrite)local.headers["if-none-match"]="*";
                local.readBody=[&](char* buffer,size_t capacity){size_t n=payload.read(buffer,capacity);if(n>remaining)throw HttpError(502,"peer sent excess content");if(EVP_DigestUpdate(hash.get(),buffer,n)!=1)throw std::runtime_error("pull hash update failed");remaining-=n;if(!remaining)finish();return n;};stored=database.handle(user,local);
            }else{
                auto local=localRequest("PUT",localPath,patch.dump());local.headers["content-type"]="application/json";if(!overwrite)local.headers["if-none-match"]="*";stored=database.handle(user,local);
            }
            Json receipt=Json::obj();receipt["source"]=Json(sourceItem);receipt["destination"]=Json(localPath);receipt["revision"]=Json::parse(stored.body).at("revision");result["imported"].array.push_back(receipt);
        }
        result["complete"]=Json::boolean(true);result["imported_count"]=Json::num(result["imported"].array.size());Response response;response.body=result.dump();return response;
    }catch(const HttpError& e){result["imported_count"]=Json::num(result["imported"].array.size());result["error"]=Json(e.what());Response response;response.status=e.status;response.body=result.dump();return response;}
    catch(const std::exception&){result["imported_count"]=Json::num(result["imported"].array.size());result["error"]=Json("pull failed; already imported items remain committed");Response response;response.status=502;response.body=result.dump();return response;}
}
}
