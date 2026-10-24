#pragma once
#include "zar_header.h"
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
namespace zar {
using ReadSource = std::function<size_t(char*,size_t)>;
// Maximum contiguous payload representable by signed 64-bit local file offsets.
static constexpr uint64_t maxStreamPayload = 0x7fffffffffffffffULL - 32768;
// Single normal Zar record with 64-bit length and constant-memory streaming.
Header writeStream(const std::filesystem::path& file, Header header,
                   const std::string& title, uint64_t length, const ReadSource& source);
class StreamReader {
    std::ifstream file;
    uint64_t start=0,position=0,remaining=0;
    uint8_t checksum[64]{};
    uint64_t checksumPosition=0;
    bool check=false;
public:
    Header header{};
    std::string title;
    explicit StreamReader(const std::filesystem::path& path);
    void range(uint64_t offset,uint64_t length);
    size_t read(char* buffer,size_t capacity);
};
}
