#include "storage.h"

namespace clientwarden::platforms {
    Storage::Storage() {
        
    }

    Storage::Storage(ItemId id) {
        
    }

    Storage::Storage(std::filesystem::path path) {
        
    }

    std::expected<std::string, StorageError> Storage::read(std::filesystem::path file, 
        std::function<void(float)> on_progress, float size) {
        return "";
    }

    std::expected<std::vector<uint8_t>, StorageError> Storage::readBinary(std::filesystem::path file, 
        std::function<void(float)> on_progress, float size) {
        std::vector<uint8_t> buffer(0);
        
        return std::move(buffer);
    }

    std::expected<Botan::secure_vector<uint8_t>, StorageError> Storage::readSecure(
        std::filesystem::path file, std::function<void(float)> on_progress, float size) {
        Botan::secure_vector<uint8_t> buffer;
        
        return std::move(buffer);
    }

    StorageError Storage::write(std::filesystem::path file, std::string data) {
        return StorageError::Success;
    }

    StorageError Storage::write(std::filesystem::path file, Botan::secure_vector<uint8_t> data) {
        return StorageError::Success;
    }

    StorageError Storage::remove(std::filesystem::path file) {
        return StorageError::Success;
    }

    StorageError Storage::rename(std::filesystem::path file, std::string name) {
        return StorageError::Success;
    }

    std::expected<bool, StorageError> Storage::exists(std::filesystem::path file) {
        return true;
    }

    std::filesystem::path Storage::getPath() {
        return m_path;
    }
}