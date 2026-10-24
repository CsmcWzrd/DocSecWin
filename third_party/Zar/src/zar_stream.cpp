#include "zar_stream.h"
#include "zar_utils.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
namespace zar {
namespace {
void checksumInit(uint8_t* out) {
    const uint64_t seed[8]={0x123456789ABCDEF0ULL,0x0FEDCBA987654321ULL,0xA5A5A5A5A5A5A5A5ULL,0x5A5A5A5A5A5A5A5AULL,0x1122334455667788ULL,0x8877665544332211ULL,0xCAFEBABEDEADBEEFULL,0x0BADC0DEFEEDFACEULL};
    std::memcpy(out,seed,64);
}
void checksumAdd(uint8_t* out,uint64_t& position,const char* data,size_t length) {
    for(size_t i=0;i<length;++i) out[(position++)%64]^=static_cast<uint8_t>(data[i]);
}
Header order(Header h,ByteOrder from,ByteOrder to) {
    h.m_nextBlock=convert64(h.m_nextBlock,from,to);h.m_prevBlock=convert64(h.m_prevBlock,from,to);
    h.m_blockCount=convert64(h.m_blockCount,from,to);h.m_timestamp=convert64(h.m_timestamp,from,to);
    h.m_id=convert64(h.m_id,from,to);h.m_flags=convert64(h.m_flags,from,to);
    for(auto& c:h.m_counters)c=convert64(c,from,to);
    h.m_dataLength=convert64(h.m_dataLength,from,to);h.m_titleLength=convert32(h.m_titleLength,from,to);h.m_extra=convert32(h.m_extra,from,to);return h;
}
}
Header writeStream(const std::filesystem::path& path,Header header,const std::string& title,uint64_t length,const ReadSource& source) {
    if(length>maxStreamPayload || title.size()>4096)throw std::runtime_error("Zar stream exceeds 64-bit file bounds");
    std::fstream file(path,std::ios::binary|std::ios::in|std::ios::out|std::ios::trunc);
    if(!file)throw std::runtime_error("cannot create Zar payload");
    std::array<char,8192> index{};uint64_t offset=convert64(kBlockSize,hostByteOrder(),kLittleEndian);std::memcpy(index.data(),&offset,8);file.write(index.data(),index.size());
    header.m_id=header.m_id?header.m_id:1;header.m_titleLength=static_cast<uint32_t>(title.size());header.m_dataLength=length;
    header.m_blockCount=(kHeaderSize+title.size()+length+kBlockSize-1)/kBlockSize;
    header.m_prevBlock=0;header.m_nextBlock=header.m_blockCount>1?2*kBlockSize:0;
    Header disk=order(header,hostByteOrder(),kLittleEndian);file.write(reinterpret_cast<const char*>(&disk),sizeof disk);file.write(title.data(),static_cast<std::streamsize>(title.size()));
    checksumInit(header.m_checksum);uint64_t checksumPosition=0;checksumAdd(header.m_checksum,checksumPosition,title.data(),title.size());
    std::array<char,65536> buffer{};uint64_t remaining=length;
    while(remaining){size_t want=static_cast<size_t>(std::min<uint64_t>(remaining,buffer.size()));size_t n=source(buffer.data(),want);if(!n||n>want)throw std::runtime_error("incomplete Zar payload source");file.write(buffer.data(),static_cast<std::streamsize>(n));if(!file)throw std::runtime_error("Zar payload write failed");checksumAdd(header.m_checksum,checksumPosition,buffer.data(),n);remaining-=n;}
    uint64_t padding=header.m_blockCount*kBlockSize-(kHeaderSize+title.size()+length);buffer.fill(0);file.write(buffer.data(),static_cast<std::streamsize>(padding));
    disk=order(header,hostByteOrder(),kLittleEndian);file.seekp(kBlockSize);file.write(reinterpret_cast<const char*>(&disk),sizeof disk);file.flush();if(!file)throw std::runtime_error("Zar payload commit failed");file.close();return header;
}
StreamReader::StreamReader(const std::filesystem::path& path) : file(path,std::ios::binary) {
    if(!file)throw std::runtime_error("cannot open Zar payload");
    file.seekg(0,std::ios::end);auto end=file.tellg();if(end<0)throw std::runtime_error("Zar payload size failed");uint64_t size=static_cast<uint64_t>(end);
    if(size<2*kBlockSize||size%kBlockSize)throw std::runtime_error("invalid Zar payload size");
    file.seekg(0);std::array<uint64_t,1024> index{};file.read(reinterpret_cast<char*>(index.data()),kBlockSize);
    if(convert64(index[0],kLittleEndian,hostByteOrder())!=kBlockSize)throw std::runtime_error("invalid Zar payload index");
    for(size_t i=1;i<index.size();++i)if(index[i])throw std::runtime_error("unexpected Zar payload index");
    file.read(reinterpret_cast<char*>(&header),sizeof header);header=order(header,kLittleEndian,hostByteOrder());
    if(!file||!header.m_id||header.m_titleLength>4096||header.m_dataLength>maxStreamPayload)throw std::runtime_error("invalid Zar payload header");
    uint64_t blocks=(kHeaderSize+header.m_titleLength+header.m_dataLength+kBlockSize-1)/kBlockSize;
    if(header.m_blockCount!=blocks||size!=(blocks+1)*kBlockSize||header.m_prevBlock||header.m_nextBlock!=(blocks>1?2*kBlockSize:0))throw std::runtime_error("invalid Zar payload layout");
    title.resize(header.m_titleLength);file.read(title.data(),header.m_titleLength);if(!file)throw std::runtime_error("truncated Zar title");
    start=kBlockSize+kHeaderSize+header.m_titleLength;range(0,header.m_dataLength);
}
void StreamReader::range(uint64_t offset,uint64_t length) {
    if(offset>header.m_dataLength||length>header.m_dataLength-offset)throw std::runtime_error("invalid Zar payload range");
    file.clear();file.seekg(static_cast<std::streamoff>(start+offset));if(!file)throw std::runtime_error("Zar payload seek failed");position=offset;remaining=length;
    check=offset==0&&length==header.m_dataLength;checksumInit(checksum);checksumPosition=0;
    if(check){checksumAdd(checksum,checksumPosition,title.data(),title.size());if(!length&&std::memcmp(checksum,header.m_checksum,64))throw std::runtime_error("Zar payload checksum failed");}
}
size_t StreamReader::read(char* data,size_t capacity) {
    size_t n=static_cast<size_t>(std::min<uint64_t>(remaining,capacity));if(!n)return 0;
    file.read(data,static_cast<std::streamsize>(n));if(static_cast<size_t>(file.gcount())!=n)throw std::runtime_error("truncated Zar payload");
    remaining-=n;position+=n;if(check){checksumAdd(checksum,checksumPosition,data,n);if(!remaining&&std::memcmp(checksum,header.m_checksum,64))throw std::runtime_error("Zar payload checksum failed");}return n;
}
}
