#include "zar_stream.h"
#include "zar_store.h"
#include "zar_utils.h"
#include <algorithm>
#include <chrono>
#include <array>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>
namespace fs=std::filesystem;
static void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
int main(){
    auto dir=fs::temp_directory_path()/("docsec-zar-stream-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));fs::create_directories(dir);
    try{
        auto path=dir/"normal.zar";std::string title="document/sections/section/data/blob";std::vector<uint8_t> expected(200003);for(size_t i=0;i<expected.size();++i)expected[i]=uint8_t(i%251);size_t pos=0;zar::Header h{};
        zar::writeStream(path,h,title,expected.size(),[&](char* out,size_t n){n=std::min(n,expected.size()-pos);std::memcpy(out,expected.data()+pos,n);pos+=n;return n;});
        zar::Store old;require(old.openSnapshot(path.string(),1024*1024),"legacy reader could not open streamed archive");std::string actualTitle,error;std::vector<uint8_t> data;
        require(old.readBinary(0,h,actualTitle,data,&error),"legacy reader checksum failed");require(data==expected&&actualTitle==title,"legacy stream interoperability failed");old.close();
        zar::StreamReader reader(path);std::array<char,37> buffer{};reader.range(65530,37);require(reader.read(buffer.data(),buffer.size())==37,"short range");require(std::memcmp(buffer.data(),expected.data()+65530,37)==0,"range content mismatch");
        // A real sparse file validates seeking/range arithmetic above 4 GiB without
        // allocating or writing 5 GiB of physical storage. Large HTTP upload is tested separately.
#ifndef _WIN32
        require(zar::hostByteOrder()==zar::kLittleEndian,"sparse fixture currently requires little-endian test host");
        auto sparse=dir/"sparse-5GiB.zar";const uint64_t length=5ULL*1024*1024*1024+123,at=4ULL*1024*1024*1024+17;
        std::fstream file(sparse,std::ios::binary|std::ios::in|std::ios::out|std::ios::trunc);std::array<char,8192> index{};uint64_t address=8192;std::memcpy(index.data(),&address,8);file.write(index.data(),index.size());
        h={};h.m_id=7;h.m_titleLength=1;h.m_dataLength=length;h.m_blockCount=(256+1+length+8191)/8192;h.m_nextBlock=16384;std::vector<uint8_t> t{'x'};zar::computeChecksum(t,h.m_checksum);h.m_checksum[(1+at)%64]^=uint8_t('Q');file.write(reinterpret_cast<char*>(&h),256);file.put('x');
        file.seekp(static_cast<std::streamoff>(8192+256+1+at));file.put('Q');file.seekp(static_cast<std::streamoff>((h.m_blockCount+1)*8192-1));file.put('\0');file.close();
        zar::StreamReader large(sparse);large.range(at-1,3);std::array<char,3> slice{};require(large.read(slice.data(),slice.size())==3,"64-bit range length failed");require(slice[0]==0&&slice[1]=='Q'&&slice[2]==0,"64-bit seek content failed");
        std::cout<<"Sparse 5 GiB offset tests passed.\n";
#endif
        fs::remove_all(dir);std::cout<<"Zar stream interoperability tests passed.\n";return 0;
    }catch(const std::exception& e){fs::remove_all(dir);std::cerr<<e.what()<<'\n';return 1;}
}
