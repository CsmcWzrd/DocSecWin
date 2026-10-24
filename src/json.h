#pragma once
#include "docsec_http.h"
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>
namespace docsec {
// Small bounded JSON value/parser. Numbers retain their original decimal digits.
struct Json {
    enum Type { Null, Bool, Number, String, Array, Object } type=Null;
    std::string text;
    std::vector<Json> array;
    std::map<std::string,Json> object;
    Json()=default;
    explicit Json(std::string s) : type(String),text(std::move(s)) {}
    Json(const char* s) : Json(std::string(s)) {}
    static Json obj() {Json v;v.type=Object;return v;}
    static Json arr() {Json v;v.type=Array;return v;}
    static Json num(uint64_t n) {Json v;v.type=Number;v.text=std::to_string(n);return v;}
    static Json boolean(bool b) {Json v;v.type=Bool;v.text=b?"true":"false";return v;}
    bool has(const std::string& key) const {return type==Object&&object.count(key);}
    const Json& at(const std::string& key) const {auto i=object.find(key);if(type!=Object||i==object.end()) throw HttpError(400,"missing JSON field: "+key);return i->second;}
    Json& operator[](const std::string& key) {if(type!=Object) throw HttpError(400,"JSON object required");return object[key];}
    std::string str() const {if(type!=String) throw HttpError(400,"JSON string required");return text;}
    uint64_t integer() const {
        if(type!=Number||text.empty()) throw HttpError(400,"unsigned integer required");
        uint64_t n=0;for(char c:text) {if(c<'0'||c>'9'||n>(UINT64_MAX-uint64_t(c-'0'))/10) throw HttpError(400,"unsigned integer out of range");n=n*10+uint64_t(c-'0');}return n;
    }
    std::string dump() const {
        if(type==Null)return "null";
        if(type==Bool||type==Number)return text;
        if(type==String)return quote(text);
        std::string s=type==Array?"[":"{";bool first=true;
        if(type==Array) for(const auto& v:array){if(!first)s+=',';first=false;s+=v.dump();}
        if(type==Object) for(const auto& v:object){if(!first)s+=',';first=false;s+=quote(v.first)+":"+v.second.dump();}
        return s+(type==Array?"]":"}");
    }
    static bool validUtf8(const std::string& s) {
        size_t i=0;while(i<s.size()) {
            unsigned char c=s[i++];if(c<128)continue;
            unsigned n;uint32_t p,min;
            if(c>=0xc2&&c<=0xdf){n=1;p=c&31;min=0x80;}
            else if(c>=0xe0&&c<=0xef){n=2;p=c&15;min=0x800;}
            else if(c>=0xf0&&c<=0xf4){n=3;p=c&7;min=0x10000;}
            else return false;
            while(n--){if(i==s.size())return false;unsigned char d=s[i++];if((d&0xc0)!=0x80)return false;p=(p<<6)|(d&63);}
            if(p<min||p>0x10ffff||(p>=0xd800&&p<=0xdfff))return false;
        }return true;
    }
    static Json parse(const std::string& data,size_t maxNodes=100000) {
        struct Parser {
            const std::string& s;size_t limit;size_t p=0,nodes=0;
            [[noreturn]] void bad(){throw HttpError(400,"invalid JSON");}
            void ws(){while(p<s.size()&&(s[p]==' '||s[p]=='\t'||s[p]=='\r'||s[p]=='\n'))++p;}
            unsigned hex4(){unsigned v=0;for(int i=0;i<4;++i){if(p==s.size())bad();char c=s[p++];unsigned d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;if(d==16)bad();v=(v<<4)|d;}return v;}
            void utf(std::string& out,unsigned c){if(c<128)out+=char(c);else if(c<2048){out+=char(0xc0|(c>>6));out+=char(0x80|(c&63));}else if(c<65536){out+=char(0xe0|(c>>12));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}else{out+=char(0xf0|(c>>18));out+=char(0x80|((c>>12)&63));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}}
            std::string string(){
                if(p==s.size()||s[p++]!='"')bad();std::string out;
                while(p<s.size()){
                    unsigned char c=s[p++];if(c=='"'){if(!Json::validUtf8(out))bad();return out;}if(c<32)bad();
                    if(c!='\\'){out+=char(c);continue;}if(p==s.size())bad();char e=s[p++];
                    switch(e){case '"':out+='"';break;case '\\':out+='\\';break;case '/':out+='/';break;case 'b':out+='\b';break;case 'f':out+='\f';break;case 'n':out+='\n';break;case 'r':out+='\r';break;case 't':out+='\t';break;
                    case 'u':{unsigned v=hex4();if(v>=0xd800&&v<=0xdbff){if(p+2>s.size()||s[p++]!='\\'||s[p++]!='u')bad();unsigned low=hex4();if(low<0xdc00||low>0xdfff)bad();v=0x10000+((v-0xd800)<<10)+(low-0xdc00);}else if(v>=0xdc00&&v<=0xdfff)bad();utf(out,v);break;}
                    default:bad();}
                }bad();
            }
            Json value(unsigned depth){
                if(depth>32||++nodes>limit)bad();ws();if(p==s.size())bad();char c=s[p];
                if(c=='"')return Json(string());
                if(c=='{'||c=='['){++p;Json v=c=='{'?Json::obj():Json::arr();ws();char close=c=='{'?'}':']';if(p<s.size()&&s[p]==close){++p;return v;}
                    for(;;){ws();if(c=='{'){auto key=string();ws();if(p==s.size()||s[p++]!=':')bad();auto item=value(depth+1);if(!v.object.emplace(key,std::move(item)).second)bad();}else v.array.push_back(value(depth+1));ws();if(p==s.size())bad();char x=s[p++];if(x==close)break;if(x!=',')bad();}return v;}
                for(const auto& literal:{std::string("null"),std::string("true"),std::string("false")})if(s.compare(p,literal.size(),literal)==0){p+=literal.size();if(literal=="null")return Json();return Json::boolean(literal=="true");}
                size_t start=p;if(s[p]=='-')++p;if(p==s.size())bad();if(s[p]=='0')++p;else{if(s[p]<'1'||s[p]>'9')bad();while(p<s.size()&&s[p]>='0'&&s[p]<='9')++p;}
                if(p<s.size()&&s[p]=='.'){++p;size_t b=p;while(p<s.size()&&s[p]>='0'&&s[p]<='9')++p;if(b==p)bad();}
                if(p<s.size()&&(s[p]=='e'||s[p]=='E')){++p;if(p<s.size()&&(s[p]=='+'||s[p]=='-'))++p;size_t b=p;while(p<s.size()&&s[p]>='0'&&s[p]<='9')++p;if(b==p)bad();}
                Json v;v.type=Number;v.text=s.substr(start,p-start);return v;
            }
        } parser{data,maxNodes};
        Json result=parser.value(0);parser.ws();if(parser.p!=data.size())parser.bad();return result;
    }
};
}
