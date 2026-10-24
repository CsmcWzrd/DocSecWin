#include "database.h"
#include "zar_store.h"
#include "zar_stream.h"
#include "zar_utils.h"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>
namespace docsec {
namespace {
constexpr uint64_t maxCatalog=64*1024*1024;
const std::string base="/api/v1/documents";
std::vector<std::string> split(const std::string& s,char delimiter='/'){
    std::vector<std::string> out;size_t start=0;for(;;){auto end=s.find(delimiter,start);out.push_back(s.substr(start,end-start));if(end==std::string::npos)break;start=end+1;}return out;
}
std::string lower(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c=char(c-'A'+'a');return s;}
std::string parent(const std::string& key){auto last=key.rfind('/');return last==std::string::npos?"":key.substr(0,key.rfind('/',last-1));}
bool keyValid(const std::string& key){auto p=split(key);if(p.size()!=1&&p.size()!=3&&p.size()!=5)return false;if(!identifier(p[0]))return false;
    if(p.size()>=3&&((p[1]!="sections"&&p[1]!="notes")||!identifier(p[2])))return false;
    return p.size()<5||(p[1]=="sections"&&(p[3]=="data"||p[3]=="notes")&&identifier(p[4]));}
std::string category(const std::string& key){auto p=split(key);return p.size()==1?"document":p[p.size()-2]=="sections"?"section":p[p.size()-2]=="notes"?"note":"data";}
bool payloadKind(const std::string& key){auto c=category(key);return c=="data"||c=="note";}
bool hexString(const std::string& s,size_t length){if(s.size()!=length)return false;for(char c:s)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true;}
bool mediaType(const std::string& s){if(s.empty()||s.size()>128||s.find('/')==std::string::npos)return false;for(unsigned char c:s)if(c<32||c>126)return false;return true;}
uint64_t number(const std::string& s){Json n;n.type=Json::Number;n.text=s;return n.integer();}
uint64_t integer(const Json& object,const std::string& key){return object.at(key).integer();}
Json initial(const std::string& key,uint64_t id,uint64_t time){
    Json m=Json::obj();auto p=split(key);m["id"]=Json(p.back());m["url"]=Json(base+"/"+key);m["resource_type"]=Json(category(key));m["archive_id"]=Json::num(id);
    for(auto name:{"created_at","updated_at","timestamp"})m[name]=Json::num(time);
    m["revision"]=Json::num(1);m["title"]=Json("");m["kind"]=Json(payloadKind(key)?(category(key)=="note"?"clob":"blob"):category(key));
    m["content_type"]=Json(payloadKind(key)?"application/octet-stream":"text/plain; charset=utf-8");m["encoding"]=Json(payloadKind(key)?"binary":"utf-8");
    m["size"]=Json::num(0);m["flags"]=Json::num(0);m["extra"]=Json::num(0);m["additional"]=Json(std::string(32,'0'));
    m["counters"]=Json::arr();for(int i=0;i<14;++i)m["counters"].array.push_back(Json::num(0));m["tags"]=Json::arr();m["attributes"]=Json::obj();m["sha256"]=Json("");m["zar_checksum"]=Json("");return m;
}
void validateAttributeDepth(const Json& value,unsigned depth=0){if(depth>16)throw HttpError(400,"attributes nesting exceeds 16 levels");for(const auto& e:value.object)validateAttributeDepth(e.second,depth+1);for(const auto& e:value.array)validateAttributeDepth(e,depth+1);}
void validateMeta(const Json& m){
    if(m.type!=Json::Object)throw HttpError(400,"metadata object required");
    auto title=m.at("title").str();if(title.size()>4096||!Json::validUtf8(title)||title.find('\0')!=std::string::npos)throw HttpError(400,"title must be UTF-8 and at most 4096 bytes");
    if(!mediaType(m.at("content_type").str()))throw HttpError(415,"invalid Content-Type");
    static const std::set<std::string> kinds={"document","section","clob","blob","json","xml","text","binary"};
    if(!kinds.count(m.at("kind").str()))throw HttpError(400,"unsupported kind");
    static const std::set<std::string> encodings={"binary","ascii","utf-8","utf-16","utf-16le","utf-16be","utf-32","utf-32le","utf-32be"};
    if(!encodings.count(m.at("encoding").str()))throw HttpError(400,"unsupported encoding");
    for(auto k:{"flags","timestamp","archive_id","created_at","updated_at","revision","size"})integer(m,k);
    if(integer(m,"extra")>UINT32_MAX||!hexString(m.at("additional").str(),32))throw HttpError(400,"invalid Zar extra/additional field");
    const auto& counters=m.at("counters");if(counters.type!=Json::Array||counters.array.size()!=14)throw HttpError(400,"counters must have exactly 14 uint64 values");for(const auto& c:counters.array)c.integer();
    const auto& tags=m.at("tags");if(tags.type!=Json::Array||tags.array.size()>64)throw HttpError(400,"tags must be an array of at most 64 strings");for(const auto& t:tags.array)if(t.str().size()>256)throw HttpError(400,"tag too long");
    validateAttributeDepth(m.at("attributes"));
    if(m.at("attributes").type!=Json::Object||m.at("attributes").dump().size()>65536)throw HttpError(400,"attributes must be an object of at most 64 KiB");
}
std::string normalizeEncoding(std::string value){value=lower(value);if(value.size()>=2&&((value.front()=='"'&&value.back()=='"')||(value.front()=='\''&&value.back()=='\'')))value=value.substr(1,value.size()-2);if(value=="utf8")value="utf-8";if(value=="utf16")value="utf-16";if(value=="utf32")value="utf-32";if(value=="us-ascii")value="ascii";return value;}
void patchMeta(Json& meta,const Json& patch){
    if(patch.type!=Json::Object)throw HttpError(400,"metadata must be a JSON object");
    static const std::set<std::string> writable={"title","content_type","kind","encoding","flags","timestamp","extra","additional","counters","tags","attributes"};
    for(const auto& p:patch.object){if(!writable.count(p.first))throw HttpError(400,"read-only or unknown metadata field: "+p.first);meta[p.first]=p.second;}
    meta["kind"]=Json(lower(meta.at("kind").str()));meta["encoding"]=Json(normalizeEncoding(meta.at("encoding").str()));
    validateMeta(meta);
}
std::string etag(const Json& m){return "\""+digest(m.dump())+"\"";}
Response jsonResponse(Json value,int status=200){Response r;r.status=status;r.body=value.dump();return r;}
const Json* field(const Json& value,const std::string& name){const Json* p=&value;for(const auto& part:split(name,'.')){
    if(p->type==Json::Object){auto i=p->object.find(part);if(i==p->object.end())return nullptr;p=&i->second;}
    else if(p->type==Json::Array){if(part.empty()||part.find_first_not_of("0123456789")!=std::string::npos)return nullptr;auto n=number(part);if(n>=p->array.size())return nullptr;p=&p->array[static_cast<size_t>(n)];}else return nullptr;
}return p;}
int compare(const Json& a,const Json& b){
    if(a.type!=b.type)return a.type<b.type?-1:1;
    if(a.type==Json::Number){
        bool ua=!a.text.empty()&&a.text.find_first_not_of("0123456789")==std::string::npos,ub=!b.text.empty()&&b.text.find_first_not_of("0123456789")==std::string::npos;
        if(ua&&ub){if(a.text.size()!=b.text.size())return a.text.size()<b.text.size()?-1:1;return a.text<b.text?-1:a.text>b.text?1:0;}
        try{long double x=std::stold(a.text),y=std::stold(b.text);if(!std::isfinite(x)||!std::isfinite(y))throw HttpError(400,"numeric selector outside supported range");return x<y?-1:x>y?1:0;}catch(const std::exception&){throw HttpError(400,"numeric selector outside supported range");}
    }
    auto x=a.type==Json::String?a.text:a.dump(),y=b.type==Json::String?b.text:b.dump();return x<y?-1:x>y?1:0;
}
void validateSelector(const Json& selector,unsigned depth=0){
    if(selector.type!=Json::Object||depth>16)throw HttpError(400,"invalid selector");
    for(const auto& f:selector.object){
        if(f.first=="$and"||f.first=="$or"){if(f.second.type!=Json::Array||f.second.array.empty())throw HttpError(400,"logical operator requires nonempty array");for(const auto& x:f.second.array)validateSelector(x,depth+1);continue;}
        if(f.first.empty()||f.first[0]=='$')throw HttpError(400,"unsupported selector operator");
        if(f.second.type!=Json::Object)continue;
        bool operators=false,literals=false;for(const auto& op:f.second.object)if(!op.first.empty()&&op.first[0]=='$')operators=true;else literals=true;
        if(operators&&literals)throw HttpError(400,"mixed selector operators and object literal");if(!operators)continue;
        for(const auto& op:f.second.object){
            if(op.first=="$eq"||op.first=="$ne"||op.first=="$gt"||op.first=="$gte"||op.first=="$lt"||op.first=="$lte")continue;
            if(op.first=="$in"){if(op.second.type!=Json::Array)throw HttpError(400,"$in requires array");continue;}
            if(op.first=="$exists"){if(op.second.type!=Json::Bool)throw HttpError(400,"$exists requires boolean");continue;}
            if(op.first=="$prefix"||op.first=="$contains"){op.second.str();continue;}
            if(op.first=="$bitsAllSet"){op.second.integer();continue;}
            throw HttpError(400,"unsupported selector operator: "+op.first);
        }
    }
}
bool matches(const Json& meta,const Json& selector){
    for(const auto& f:selector.object){
        if(f.first=="$and"||f.first=="$or"){bool result=f.first=="$and";for(const auto& s:f.second.array){bool m=matches(meta,s);if(f.first=="$and")result=result&&m;else result=result||m;}if(!result)return false;continue;}
        auto p=field(meta,f.first);bool operators=f.second.type==Json::Object&&!f.second.object.empty()&&!f.second.object.begin()->first.empty()&&f.second.object.begin()->first[0]=='$';
        if(!operators){if(!p||compare(*p,f.second))return false;continue;}
        for(const auto& op:f.second.object){
            if(op.first=="$exists"){if(bool(p)!=(op.second.text=="true"))return false;continue;}
            if(!p)return false;
            if(op.first=="$in"){bool found=false;for(const auto& v:op.second.array)if(!compare(*p,v))found=true;if(!found)return false;continue;}
            if(op.first=="$prefix"){if(p->type!=Json::String||p->text.compare(0,op.second.text.size(),op.second.text))return false;continue;}
            if(op.first=="$contains"){bool found=p->type==Json::String&&p->text.find(op.second.text)!=std::string::npos;if(p->type==Json::Array)for(const auto& v:p->array)if(v.type==Json::String&&v.text==op.second.text)found=true;if(!found)return false;continue;}
            if(op.first=="$bitsAllSet"){if(p->type!=Json::Number||(p->integer()&op.second.integer())!=op.second.integer())return false;continue;}
            int c=compare(*p,op.second);if((op.first=="$eq"&&c)||(op.first=="$ne"&&!c)||(op.first=="$gt"&&c<=0)||(op.first=="$gte"&&c<0)||(op.first=="$lt"&&c>=0)||(op.first=="$lte"&&c>0))return false;
        }
    }return true;
}
std::string unescape(const std::string& s){std::string out;for(size_t i=0;i<s.size();++i){char c=s[i];if(c=='+')c=' ';else if(c=='%'){if(i+2>=s.size())throw HttpError(400,"invalid URL escape");auto digit=[](char x)->int{return x>='0'&&x<='9'?x-'0':x>='a'&&x<='f'?x-'a'+10:x>='A'&&x<='F'?x-'A'+10:-1;};int a=digit(s[++i]),b=digit(s[++i]);if(a<0||b<0)throw HttpError(400,"invalid URL escape");c=char(a*16+b);}if(!c)throw HttpError(400,"NUL in query");out+=c;}if(!Json::validUtf8(out))throw HttpError(400,"query must be UTF-8");return out;}
std::map<std::string,std::string> queryMap(const std::string& query){std::map<std::string,std::string> out;if(query.empty())return out;for(auto& s:split(query,'&')){auto p=s.find('=');auto key=unescape(s.substr(0,p));auto value=p==std::string::npos?"":unescape(s.substr(p+1));if(!out.emplace(key,value).second)throw HttpError(400,"duplicate query parameter");}return out;}
struct Hash {
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(),EVP_MD_CTX_free};
    Hash(){if(!context||EVP_DigestInit_ex(context.get(),EVP_sha256(),nullptr)!=1)throw std::runtime_error("SHA256 init failed");}
    void add(const char* data,size_t n){if(EVP_DigestUpdate(context.get(),data,n)!=1)throw std::runtime_error("SHA256 update failed");}
    std::string finish(){uint8_t sum[32];unsigned n=0;if(EVP_DigestFinal_ex(context.get(),sum,&n)!=1||n!=32)throw std::runtime_error("SHA256 finish failed");return zar::bytesToHex(sum,32);}
};
struct LegacyReader{const std::string& s;size_t p=0;uint64_t number(){if(s.size()-p<8)throw std::runtime_error("truncated legacy catalog");uint64_t n=0;for(int i=0;i<8;++i)n|=uint64_t(static_cast<unsigned char>(s[p++]))<<(i*8);return n;}std::string string(){auto n=number();if(n>s.size()-p)throw std::runtime_error("invalid legacy length");auto v=s.substr(p,static_cast<size_t>(n));p+=static_cast<size_t>(n);return v;}};
}
void Database::storePayload(const fs::path& dir,const std::string& key,Entity& e,uint64_t length,const std::function<size_t(char*,size_t)>& source){
    privateDirectory(dir/"payloads");auto id=randomHex(16);auto temp=dir/"payloads"/(id+".tmp"),file=dir/"payloads"/(id+".zar");Hash hash;
    zar::Header header{};header.m_id=integer(e.meta,"archive_id");header.m_timestamp=integer(e.meta,"timestamp");header.m_flags=integer(e.meta,"flags");header.m_extra=static_cast<uint32_t>(integer(e.meta,"extra"));
    for(size_t i=0;i<14;++i)header.m_counters[i]=e.meta.at("counters").array[i].integer();auto additional=zar::hexToBytes(e.meta.at("additional").str());std::memcpy(header.m_additional,additional.data(),16);
    try{header=zar::writeStream(temp,header,key,length,[&](char* buffer,size_t n){size_t got=source(buffer,n);if(got>n)throw std::runtime_error("invalid payload source");hash.add(buffer,got);return got;});
        e.meta["size"]=Json::num(length);e.meta["sha256"]=Json(hash.finish());e.meta["zar_checksum"]=Json(zar::bytesToHex(header.m_checksum,64));atomicReplace(temp,file);e.blob=id;e.legacy.clear();e.legacyData=false;
    }catch(...){std::error_code ec;fs::remove(temp,ec);throw;}
}
Database::Entities Database::load(const fs::path& path){
    rejectSymlink(path);if(!fs::exists(path))throw std::runtime_error("user archive missing");zar::Store archive;
    if(!archive.openSnapshot(path.string(),maxCatalog+32768))throw std::runtime_error("invalid catalog archive");
    zar::Header header{};std::string title,error;std::vector<uint8_t> bytes;
    if(!archive.readBinary(0,header,title,bytes,&error)||bytes.size()<64)throw std::runtime_error("corrupt catalog");
    std::string sum(bytes.begin(),bytes.begin()+64),payload(bytes.begin()+64,bytes.end());if(sum!=digest(payload))throw std::runtime_error("catalog digest mismatch");Entities entities;
    if(title=="DocSecWin-snapshot-v1"){
        LegacyReader reader{payload};if(reader.string()!="DocSecWin/1")throw std::runtime_error("invalid legacy schema");uint64_t count=reader.number();if(count>10000)throw std::runtime_error("legacy entity limit");
        for(uint64_t i=0;i<count;++i){auto key=reader.string(),type=reader.string(),body=reader.string();uint64_t revision=reader.number();if(!keyValid(key))throw std::runtime_error("invalid legacy key");Entity e;e.meta=initial(key,i+1,0);e.meta["revision"]=Json::num(revision);e.meta["content_type"]=Json(type);e.meta["size"]=Json::num(body.size());
            if(payloadKind(key)){e.legacy=body;e.legacyData=true;e.meta["sha256"]=Json(digest(body));}else e.meta["title"]=Json(body);
            if(!entities.emplace(key,std::move(e)).second)throw std::runtime_error("duplicate legacy entity");}
        if(reader.p!=payload.size())throw std::runtime_error("trailing legacy bytes");
    }else if(title=="DocSecWin-catalog-v2"){
        auto catalog=Json::parse(payload,1000000);if(catalog.at("schema").str()!="DocSecWin/2"||catalog.at("entities").type!=Json::Object)throw std::runtime_error("invalid catalog schema");
        for(const auto& entry:catalog.at("entities").object){Entity e;e.meta=entry.second.at("meta");e.blob=entry.second.at("blob").str();if(!keyValid(entry.first)||(!e.blob.empty()&&!hexString(e.blob,32)))throw std::runtime_error("invalid catalog reference");validateMeta(e.meta);
            if(e.meta.at("url").str()!=base+"/"+entry.first||e.meta.at("resource_type").str()!=category(entry.first)||e.meta.at("id").str()!=split(entry.first).back()||(payloadKind(entry.first)&&e.blob.empty()))throw std::runtime_error("inconsistent catalog metadata");entities.emplace(entry.first,std::move(e));}
    }else throw std::runtime_error("unsupported catalog version");
    if(entities.size()>10000)throw std::runtime_error("entity limit exceeded");for(const auto& e:entities){auto p=parent(e.first);if(!p.empty()&&!entities.count(p))throw std::runtime_error("orphan entity");}return entities;
}
void Database::save(const fs::path& path,Entities& entities){
    if(entities.size()>10000)throw HttpError(413,"catalog entity limit exceeded");Json catalog=Json::obj();catalog["schema"]=Json("DocSecWin/2");catalog["entities"]=Json::obj();
    for(auto& entry:entities){auto& e=entry.second;if(e.legacyData){size_t pos=0;auto data=e.legacy;storePayload(path.parent_path(),entry.first,e,data.size(),[&](char* out,size_t n){n=std::min(n,data.size()-pos);std::memcpy(out,data.data()+pos,n);pos+=n;return n;});}
        Json v=Json::obj();v["meta"]=e.meta;v["blob"]=Json(e.blob);catalog["entities"][entry.first]=std::move(v);}
    auto payload=catalog.dump();if(payload.size()>maxCatalog)throw HttpError(413,"metadata catalog exceeds 64 MiB");payload=digest(payload)+payload;
    auto temp=path.parent_path()/("catalog-"+randomHex(16)+".tmp");try{zar::Store archive;if(!archive.open(temp.string(),true))throw std::runtime_error("cannot create catalog");zar::Header header{};header.m_extra=2;uint64_t id;std::string error;std::vector<uint8_t> bytes(payload.begin(),payload.end());
        if(!archive.append(header,"DocSecWin-catalog-v2",bytes,&id,&error)||!archive.save())throw std::runtime_error("catalog write failed");archive.close();atomicReplace(temp,path);
    }catch(...){std::error_code ec;fs::remove(temp,ec);throw;}
}
void Database::initialize(const std::string& user){std::lock_guard<std::mutex> guard(mutex);auto path=root/"users"/digest(user)/"documents.zar";rejectSymlink(path);if(fs::exists(path))throw std::runtime_error("archive exists");Entities e;save(path,e);}
uint64_t Database::collectGarbage(const std::string& user){std::lock_guard<std::mutex> guard(mutex);if(!identifier(user))throw std::runtime_error("invalid username");auto dir=root/"users"/digest(user);auto entities=load(dir/"documents.zar");std::set<std::string> used;for(const auto& e:entities)if(!e.second.blob.empty())used.insert(e.second.blob+".zar");auto folder=dir/"payloads";rejectSymlink(folder);uint64_t count=0;if(fs::exists(folder))for(const auto& f:fs::directory_iterator(folder)){auto name=f.path().filename().string();rejectSymlink(f.path());if(f.is_regular_file()&&((f.path().extension()==".zar"&&!used.count(name))||f.path().extension()==".tmp")){fs::remove(f.path());++count;}}return count;}
namespace {
struct Plan {
    Json selector=Json::obj();std::vector<std::pair<std::string,bool>> sort{{"id",false}};
    std::vector<std::string> fields;uint64_t limit=100,skip=0;bool recursive=false;std::string snapshot;
};
void sortPlan(Plan& p,const Json& spec,const std::string& defaultOrder="asc"){
    auto add=[&](const std::string& name,const std::string& order){if(name.empty()||(order!="asc"&&order!="desc"))throw HttpError(400,"sort order must be asc or desc");p.sort.emplace_back(name,order=="desc");};p.sort.clear();
    if(spec.type==Json::String)add(spec.str(),defaultOrder);
    else if(spec.type==Json::Array&&spec.array.size()<=3&&!spec.array.empty()){for(const auto& s:spec.array){if(s.type!=Json::Object||s.object.size()!=1)throw HttpError(400,"each sort entry must have one field");add(s.object.begin()->first,s.object.begin()->second.str());}}
    else throw HttpError(400,"sort must be a field or up to three field/order objects");
}
Plan planFrom(const std::map<std::string,std::string>& q,const Json* body){
    Plan p;std::string order="asc";
    if(body){if(body->type!=Json::Object)throw HttpError(400,"find body must be an object");for(const auto& item:body->object){const auto& k=item.first;const auto& v=item.second;
        if(k=="selector")p.selector=v;else if(k=="sort")sortPlan(p,v);else if(k=="limit")p.limit=v.integer();else if(k=="skip"||k=="offset")p.skip=v.integer();
        else if(k=="fields"){if(v.type!=Json::Array)throw HttpError(400,"fields must be an array");for(const auto& f:v.array)p.fields.push_back(f.str());}
        else if(k=="recursive"){if(v.type!=Json::Bool)throw HttpError(400,"recursive must be boolean");p.recursive=v.text=="true";}else if(k=="snapshot")p.snapshot=v.str();else throw HttpError(400,"unknown find option: "+k);
    }}
    auto condition=[&](const std::string& fieldName,const std::string& op,Json value){if(!p.selector.has(fieldName))p.selector[fieldName]=Json::obj();if(p.selector[fieldName].type!=Json::Object)throw HttpError(400,"conflicting selector");p.selector[fieldName][op]=std::move(value);};
    for(const auto& entry:q){const auto& k=entry.first;const auto& v=entry.second;
        if(k=="limit")p.limit=number(v);else if(k=="offset"||k=="skip")p.skip=number(v);else if(k=="order"){if(v!="asc"&&v!="desc")throw HttpError(400,"invalid order");order=v;}
        else if(k=="fields")p.fields=split(v,',');else if(k=="recursive"){if(v!="true"&&v!="false")throw HttpError(400,"invalid recursive boolean");p.recursive=v=="true";}
        else if(k=="snapshot")p.snapshot=v;else if(k=="sort"){}
        else if(k=="selector"){if(body)throw HttpError(400,"selector cannot appear in query and find body");auto selector=Json::parse(v);if(!p.selector.object.empty())throw HttpError(400,"use either selector or simple filters");p.selector=selector;}
        else if(k=="id"||k=="kind"||k=="content_type"||k=="encoding"||k=="sha256"||k=="additional"||k=="resource_type")condition(k,"$eq",Json(v));
        else if(k=="checksum"||k=="zar_checksum")condition("zar_checksum","$eq",Json(v));
        else if(k=="title_prefix")condition("title","$prefix",Json(v));else if(k=="tag")condition("tags","$contains",Json(v));
        else if(k=="flags"||k=="extra"||k=="timestamp"||k=="archive_id")condition(k,"$eq",Json::num(number(v)));
        else if(k=="flags_all")condition("flags","$bitsAllSet",Json::num(number(v)));
        else {
            bool bound=false;for(const auto& fieldName:{std::string("archive_id"),std::string("id"),std::string("timestamp"),std::string("created_at"),std::string("updated_at"),std::string("size"),std::string("revision")})
                for(const auto& suffix:{std::string("_min"),std::string("_max")})if(k==fieldName+suffix){condition(fieldName=="id"?"archive_id":fieldName,suffix=="_min"?"$gte":"$lte",Json::num(number(v)));bound=true;}
            for(unsigned i=0;i<14;++i)for(const auto& suffix:{std::string(""),std::string("_min"),std::string("_max")})if(k=="counter"+std::to_string(i)+suffix){condition("counters."+std::to_string(i),suffix.empty()?"$eq":suffix=="_min"?"$gte":"$lte",Json::num(number(v)));bound=true;}
            if(!bound)throw HttpError(400,"unsupported query option: "+k);
        }
    }
    if(q.count("sort"))sortPlan(p,Json(q.at("sort")),order);else if(q.count("order"))for(auto& item:p.sort)item.second=order=="desc";
    if(p.limit<1||p.limit>1000)throw HttpError(400,"limit must be 1-1000");if(p.fields.size()>64)throw HttpError(400,"too many projection fields");
    for(const auto& f:p.fields)if(f.empty()||f.find('.')!=std::string::npos)throw HttpError(400,"projection fields must be top-level metadata names");validateSelector(p.selector);return p;
}
}
Response Database::handle(const std::string& user,const Request& r){
    std::lock_guard<std::mutex> guard(mutex);
    auto dir=root/"users"/digest(user);rejectSymlink(dir);auto path=dir/"documents.zar";auto entities=load(path);
    auto question=r.target.find('?');auto target=r.target.substr(0,question);auto q=queryMap(question==std::string::npos?"":r.target.substr(question+1));
    if(target!=base&&target.compare(0,base.size()+1,base+"/")!=0)throw HttpError(404,"endpoint not found");
    auto key=target==base?"":target.substr(base.size()+1);bool find=false,metadata=false,verify=false;
    if(key=="_find"){key="";find=true;}else if(key.size()>6&&key.substr(key.size()-6)=="/_find"){key.resize(key.size()-6);find=true;}
    for(const auto& suffix:{std::string("/metadata"),std::string("/verify")})if(key.size()>suffix.size()&&key.substr(key.size()-suffix.size())==suffix&&keyValid(key.substr(0,key.size()-suffix.size()))){key.resize(key.size()-suffix.size());metadata=suffix=="/metadata";verify=suffix=="/verify";break;}
    auto parts=split(key);bool collection=key.empty()||(parts.size()==2&&identifier(parts[0])&&(parts[1]=="sections"||parts[1]=="notes"))||(parts.size()==4&&identifier(parts[0])&&parts[1]=="sections"&&identifier(parts[2])&&(parts[3]=="data"||parts[3]=="notes"));
    if((!collection&&!keyValid(key))||((metadata||verify)&&collection)||(find&&!collection))throw HttpError(400,"invalid hierarchy or identifier");
    auto method=r.method=="HEAD"?"GET":r.method;bool create=collection&&method=="POST"&&!find;
    std::string parentKey=collection?(key.empty()?"":key.substr(0,key.rfind('/'))):parent(key);
    if(!parentKey.empty()&&!entities.count(parentKey))throw HttpError(404,"parent not found");
    Json creationPatch=Json::obj();std::string createdId;
    if(create){
        if(!q.empty())throw HttpError(400,"creation query options unsupported");bool titles=key.empty()||parts.back()=="sections";
        if(titles){creationPatch=Json::parse(r.readText(256*1024));if(creationPatch.type!=Json::Object)throw HttpError(400,"creation JSON object required");if(creationPatch.has("id")){createdId=creationPatch.at("id").str();creationPatch.object.erase("id");}}
        auto idHeader=r.headers.find("x-docsec-id");if(idHeader!=r.headers.end()){if(!createdId.empty()&&createdId!=idHeader->second)throw HttpError(400,"conflicting resource IDs");createdId=idHeader->second;}
        if(createdId.empty())createdId=randomHex(16);if(!identifier(createdId)||createdId=="_find")throw HttpError(400,"invalid ID");key=key.empty()?createdId:key+"/"+createdId;target=base+"/"+key;parts=split(key);collection=false;
        if(entities.count(key))throw HttpError(409,"resource ID already exists");
    }
    if(collection){
        if(find&&r.method!="POST")throw HttpError(405,"_find requires POST","POST");
        if(!find&&method!="GET")throw HttpError(405,"collection supports GET, HEAD and POST","GET, HEAD, POST");
        Json request;if(find)request=Json::parse(r.readText(256*1024));Plan plan=planFrom(q,find?&request:nullptr);
        std::string fingerprint;for(const auto& entry:entities)fingerprint+=entry.first+"\n"+entry.second.meta.dump()+"\n";auto snapshot=digest(fingerprint);
        if(!plan.snapshot.empty()&&plan.snapshot!=snapshot)throw HttpError(409,"catalog changed; restart pagination");
        std::vector<const Entity*> selected;std::string prefix=parentKey.empty()?"":parentKey+"/";
        for(const auto& entry:entities){bool scope=parent(entry.first)==parentKey;if(!key.empty())scope=scope&&entry.first.compare(0,key.size()+1,key+"/")==0;
            if(plan.recursive)scope=key.empty()||entry.first.compare(0,key.size()+1,key+"/")==0;
            if(scope&&matches(entry.second.meta,plan.selector))selected.push_back(&entry.second);}
        std::sort(selected.begin(),selected.end(),[&](const Entity* a,const Entity* b){for(const auto& order:plan.sort){auto x=field(a->meta,order.first),y=field(b->meta,order.first);int c=x&&y?compare(*x,*y):x?1:y?-1:0;if(c)return order.second?c>0:c<0;}
            auto ai=integer(a->meta,"archive_id"),bi=integer(b->meta,"archive_id");if(ai!=bi)return ai<bi;return a->meta.at("url").str()<b->meta.at("url").str();});
        Json result=Json::obj();result["items"]=Json::arr();uint64_t end=std::min<uint64_t>(selected.size(),plan.skip>selected.size()?selected.size():plan.skip+plan.limit);
        for(uint64_t i=std::min<uint64_t>(plan.skip,selected.size());i<end;++i){Json item=selected[static_cast<size_t>(i)]->meta;if(!plan.fields.empty()){item=Json::obj();for(const auto& f:plan.fields)if(selected[static_cast<size_t>(i)]->meta.has(f))item[f]=selected[static_cast<size_t>(i)]->meta.at(f);}result["items"].array.push_back(std::move(item));}
        result["total_count"]=Json::num(selected.size());result["returned_count"]=Json::num(result["items"].array.size());result["next_offset"]=end<selected.size()?Json::num(end):Json();result["snapshot"]=Json(snapshot);return jsonResponse(result);
    }
    if(find)throw HttpError(400,"find requires a collection");
    if(!q.empty()&&!(method=="DELETE"&&q.size()==1&&q.count("recursive")&&q.at("recursive")=="true"))throw HttpError(400,"item query options unsupported");
    auto found=entities.find(key);bool exists=found!=entities.end();
    if(metadata&&method!="GET"&&method!="PATCH")throw HttpError(405,"metadata supports GET, HEAD and PATCH","GET, HEAD, PATCH");
    if(verify&&(method!="GET"||!payloadKind(key)))throw HttpError(405,"verify supports GET on data or notes","GET");
    auto conditional=r.headers.find("if-match");if(conditional!=r.headers.end()&&(!exists||(conditional->second!="*"&&conditional->second!=etag(found->second.meta))))throw HttpError(412,"If-Match failed");
    if((method=="PUT"||create)&&r.headers.count("if-none-match")&&r.headers.at("if-none-match")=="*"&&exists)throw HttpError(412,"resource already exists");
    if(method=="PUT"||method=="PATCH"||create){
        if(method=="PATCH"&&!exists)throw HttpError(404,"item not found");if(verify)throw HttpError(405,"verify supports GET","GET");
        uint64_t highId=0,latest=0;for(const auto& e:entities){highId=std::max(highId,integer(e.second.meta,"archive_id"));latest=std::max(latest,integer(e.second.meta,"updated_at"));}
        auto now=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count());if(latest==UINT64_MAX||highId==UINT64_MAX)throw HttpError(507,"catalog sequence exhausted");now=std::max(now,latest+1);
        Entity e=exists?found->second:Entity{};if(!exists)e.meta=initial(key,highId+1,now);else{auto rev=integer(e.meta,"revision");if(rev==UINT64_MAX)throw HttpError(507,"revision exhausted");e.meta["revision"]=Json::num(rev+1);}
        e.meta["updated_at"]=Json::num(now);e.meta["timestamp"]=Json::num(now);
        if(method=="PATCH")patchMeta(e.meta,Json::parse(r.readText(256*1024)));
        else if(!payloadKind(key)){
            if(create)patchMeta(e.meta,creationPatch);
            else {auto body=r.readText(256*1024);auto type=r.headers.find("content-type");if(type!=r.headers.end()&&lower(type->second).find("application/json")==0)patchMeta(e.meta,Json::parse(body));else e.meta["title"]=Json(body);}
            validateMeta(e.meta);e.meta["size"]=Json::num(e.meta.at("title").text.size());e.meta["sha256"]=Json(digest(e.meta.at("title").str()));
        }else{
            auto type=r.headers.find("content-type");std::string contentType=type==r.headers.end()?(category(key)=="note"?"text/plain; charset=utf-8":"application/octet-stream"):type->second;auto lc=lower(contentType);
            e.meta["content_type"]=Json(contentType);e.meta["kind"]=Json(category(key)=="note"?"clob":lc.find("json")!=std::string::npos?"json":lc.find("xml")!=std::string::npos?"xml":lc.compare(0,5,"text/")==0?"text":"blob");
            std::string encoding="binary";if(lc.compare(0,5,"text/")==0||lc.find("json")!=std::string::npos||lc.find("xml")!=std::string::npos)encoding="utf-8";auto charset=lc.find("charset=");if(charset!=std::string::npos){encoding=lc.substr(charset+8);auto end=encoding.find_first_of("; \t");encoding=encoding.substr(0,end);if(encoding=="us-ascii")encoding="ascii";}
            e.meta["encoding"]=Json(encoding);
            for(const auto& fieldName:{"kind","encoding","title","flags","extra","additional","timestamp","counters"}){
                auto i=r.headers.find(std::string("x-docsec-")+fieldName);if(i==r.headers.end())continue;
                if(std::string(fieldName)=="counters")e.meta[fieldName]=Json::parse(i->second);else if(std::string(fieldName)=="flags"||std::string(fieldName)=="extra"||std::string(fieldName)=="timestamp")e.meta[fieldName]=Json::num(number(i->second));else e.meta[fieldName]=Json(i->second);
            }
            e.meta["kind"]=Json(lower(e.meta.at("kind").str()));e.meta["encoding"]=Json(normalizeEncoding(e.meta.at("encoding").str()));
            if(!r.internalMetadata.empty())patchMeta(e.meta,Json::parse(r.internalMetadata));
            validateMeta(e.meta);storePayload(dir,key,e,r.bodyLength,r.readBody?r.readBody:[](char*,size_t){return size_t(0);});
        }
        if(method=="PATCH"&&!payloadKind(key)){e.meta["size"]=Json::num(e.meta.at("title").text.size());e.meta["sha256"]=Json(digest(e.meta.at("title").str()));}
        entities[key]=e;save(path,entities);Response response=jsonResponse(e.meta,exists?200:201);response.headers["Location"]=base+"/"+key;response.headers["ETag"]=etag(e.meta);return response;
    }
    if(!exists)throw HttpError(404,"item not found");auto& e=found->second;
    if(method=="GET"){
        Response response;response.headers["ETag"]=etag(e.meta);response.headers["Accept-Ranges"]="bytes";
        if(r.headers.count("if-none-match")&&(r.headers.at("if-none-match")=="*"||r.headers.at("if-none-match")==etag(e.meta))){response.status=304;response.advertisedLength=metadata||!payloadKind(key)?e.meta.dump().size():integer(e.meta,"size");return response;}
        if(metadata||!payloadKind(key)){response.body=e.meta.dump();return response;}
        uint64_t size=integer(e.meta,"size"),offset=0,length=size;bool partial=false;
        auto range=r.headers.find("range");if(range!=r.headers.end()&&(!r.headers.count("if-range")||r.headers.at("if-range")==etag(e.meta))){
            bool valid=true;const auto& value=range->second;if(value.compare(0,6,"bytes=")||value.find(',')!=std::string::npos)valid=false;
            else{auto bounds=split(value.substr(6),'-');if(bounds.size()!=2||(!size)||(bounds[0].empty()&&bounds[1].empty()))valid=false;
                else{try{if(bounds[0].empty()){auto suffix=number(bounds[1]);if(!suffix)valid=false;else{length=std::min(suffix,size);offset=size-length;}}
                    else{offset=number(bounds[0]);uint64_t last=bounds[1].empty()?size-1:number(bounds[1]);if(offset>=size||last<offset)valid=false;else{last=std::min(last,size-1);length=last-offset+1;}}}catch(const HttpError&){valid=false;}}}
            if(!valid){response.status=416;response.headers["Content-Range"]="bytes */"+std::to_string(size);response.body="{\"error\":\"invalid or unsatisfiable byte range\"}";return response;}partial=true;
        }
        if(verify&&(partial||!q.empty()))throw HttpError(400,"verify does not accept ranges or queries");
        response.type=e.meta.at("content_type").str();response.headers["X-Content-SHA256"]=e.meta.at("sha256").str();response.headers["X-Zar-Checksum"]=e.meta.at("zar_checksum").str();
        if(e.legacyData){
            if(verify){Json result=Json::obj();result["verified"]=Json::boolean(digest(e.legacy)==e.meta.at("sha256").str());return jsonResponse(result);}
            response.body=e.legacy.substr(static_cast<size_t>(offset),static_cast<size_t>(length));
        }else{
            auto file=dir/"payloads"/(e.blob+".zar");rejectSymlink(file);auto reader=std::make_shared<zar::StreamReader>(file);
            if(reader->header.m_dataLength!=size||reader->title!=key||reader->header.m_id!=integer(e.meta,"archive_id")||zar::bytesToHex(reader->header.m_checksum,64)!=e.meta.at("zar_checksum").str())throw std::runtime_error("payload/catalog mismatch");
            if(verify){Hash hash;std::array<char,65536> buffer{};for(;;){size_t n=reader->read(buffer.data(),buffer.size());if(!n)break;hash.add(buffer.data(),n);}if(hash.finish()!=e.meta.at("sha256").str())throw std::runtime_error("SHA256 verification failed");Json result=Json::obj();result["verified"]=Json::boolean(true);result["sha256"]=e.meta.at("sha256");result["size"]=e.meta.at("size");return jsonResponse(result);}
            reader->range(offset,length);response.streamLength=length;auto hash=std::make_shared<Hash>();auto remaining=std::make_shared<uint64_t>(length);bool full=!partial;auto expected=e.meta.at("sha256").str();
            if(full&&!length&&digest("")!=expected)throw std::runtime_error("empty payload digest failed");
            response.readStream=[reader,hash,remaining,full,expected](char* buffer,size_t capacity){size_t n=reader->read(buffer,capacity);if(full){hash->add(buffer,n);*remaining-=n;if(!*remaining&&hash->finish()!=expected)throw std::runtime_error("SHA256 verification failed");}return n;};
        }
        if(partial){response.status=206;response.headers["Content-Range"]="bytes "+std::to_string(offset)+"-"+std::to_string(offset+length-1)+"/"+std::to_string(size);}return response;
    }
    if(method=="DELETE"){
        if(metadata||verify)throw HttpError(405,"endpoint cannot be deleted","GET, HEAD, PATCH");std::string prefix=key+"/";auto next=entities.lower_bound(prefix);bool children=next!=entities.end()&&next->first.compare(0,prefix.size(),prefix)==0;
        if(children&&!q.count("recursive"))throw HttpError(409,"item has children; use ?recursive=true");while(next!=entities.end()&&next->first.compare(0,prefix.size(),prefix)==0)next=entities.erase(next);entities.erase(key);save(path,entities);Response response;response.status=204;return response;
    }
    throw HttpError(405,"supported item methods: GET, HEAD, PUT, PATCH, DELETE","GET, HEAD, PUT, PATCH, DELETE");
}
}
