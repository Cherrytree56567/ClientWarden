#pragma once
#include <spdlog/spdlog.h>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>

namespace clientwarden::platforms {
    enum class StorageError {
        NotFound,
        Unknown,
        Success
    };

    class Storage {
    public:
        Storage(); // App/Bundle Dir
        Storage(ItemId id); // App Support Dir
        Storage(std::filesystem::path path); // Custom Path Dir
        
        std::expected<std::string, StorageError> read(std::filesystem::path file);
        std::expected<std::vector<uint8_t>, StorageError> readBinary(std::filesystem::path file);
        StorageError write(std::filesystem::path file, std::string data);
        StorageError write(std::filesystem::path file, std::vector<uint8_t> data);
        StorageError remove(std::filesystem::path file);
        StorageError rename(std::filesystem::path file, std::string name);
        std::expected<bool, StorageError> exists(std::filesystem::path file);
    public:
        std::filesystem::path m_path;
    };
}