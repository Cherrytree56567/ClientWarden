#pragma once
#include <spdlog/spdlog.h>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <shlobj.h>

class Storage {
public:
    Storage();
    Storage(std::string); // Local Path

    std::string read(std::filesystem::path file);
    std::vector<uint8_t> readBinary(std::filesystem::path file);
    void write(std::filesystem::path file, std::string data);
    void write(std::filesystem::path file, std::vector<uint8_t> data);
    void remove(std::filesystem::path file);
    void rename(std::filesystem::path file, std::string name);
    bool exists(std::filesystem::path file);
public:
    std::filesystem::path path;
};