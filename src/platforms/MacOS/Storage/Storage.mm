#include "Storage.h"

#import <Cocoa/Cocoa.h>

namespace clientwarden::platforms {
    Storage::Storage() {
        NSBundle* bundle = [NSBundle mainBundle];

        if ([bundle bundleIdentifier] != nil) {
            NSString* appPath = [[NSBundle mainBundle] bundlePath];
            std::string appDir([appPath UTF8String]);
            path = std::filesystem::path(appDir);
        } else {
            NSString* appPath = [[NSBundle mainBundle] executablePath];
            std::string appDir([appPath UTF8String]);
            path = std::filesystem::path(appDir).parent_path();
        }

        path.append("Contents");
        path.append("Resources");
    }

    Storage::Storage(ItemId id) {
        /*
        * https://stackoverflow.com/questions/8430777/programmatically-get-path-to-application-support-folder
        */
        NSArray* paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* applicationSupportDirectory = [paths firstObject];

        std::string as_dir([applicationSupportDirectory UTF8String]);

        path = std::filesystem::path(as_dir);
        path.append("ClientWarden");
        path.append(id);

        /*
        * Create a Dir
        * https://en.cppreference.com/w/cpp/filesystem/create_directory.html
        */
        try {
            std::filesystem::create_directories(path);
        } catch (...) {
            spdlog::error("Failed to create cw path");
        }
    }

    Storage::Storage(std::filesystem::path path) {
        m_path = path;

        /*
        * Create a Dir
        * https://en.cppreference.com/w/cpp/filesystem/create_directory.html
        */
        try {
            std::filesystem::create_directories(m_path);
        } catch (...) {
            
        }
    }

    std::expected<std::string, StorageError> Storage::read(std::filesystem::path file) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        if (!std::filesystem::exists(file_path)) {
            return std::unxpected(StorageError::NotFound);
        }

        std::ifstream file_stream(file_path, std::ios::in | std::ios::binary);
        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        return std::string(
            (std::istreambuf_iterator<char>(file_stream)),
            std::istreambuf_iterator<char>()
        );
    }

    std::expected<std::vector<uint8_t>, StorageError> Storage::readBinary(
        std::filesystem::path file) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        if (!std::filesystem::exists(file_path)) {
            return std::unxpected(StorageError::NotFound);
        }

        std::uintmax_t size = std::filesystem::file_size(file_path);

        std::ifstream file_stream(file_path, std::ios::binary);
        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        std::vector<uint8_t> buffer(size);

        file_stream.read(reinterpret_cast<char*>(buffer.data()), size);

        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        return std::move(buffer);
    }

    StorageError Storage::write(std::filesystem::path file, std::string data) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        std::filesystem::create_directories(file_path.parent_path());

        std::ofstream file_stream(file_path, std::ios::binary);
        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        file_stream.write(data.data(), data.size());

        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        return StorageError::Success;
    }

    StorageError Storage::write(std::filesystem::path file, std::vector<uint8_t> data) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        std::filesystem::create_directories(file_path.parent_path());

        std::ofstream file_stream(file_path, std::ios::binary);
        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        file_stream.write(reinterpret_cast<const char*>(data.data()), data.size());

        if (!file_stream) {
            return std::unxpected(StorageError::Unknown);
        }

        return StorageError::Success;
    }

    StorageError Storage::remove(std::filesystem::path file) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        if (!std::filesystem::exists(file_path)) {
            return StorageError::NotFound;
        }

        if (!std::filesystem::remove(file_path)) {
            return StorageError::Unknown;
        }

        return StorageError::Success;
    }

    StorageError Storage::rename(std::filesystem::path file, std::string name) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        if (!std::filesystem::exists(file_path)) {
            return StorageError::NotFound;
        }

        std::filesystem::path new_path = file_path.parent_path() / name;

        std::filesystem::rename(file_path, new_path);

        return StorageError::Success;
    }

    std::expected<bool, StorageError> Storage::exists(std::filesystem::path file) {
        std::filesystem::path file_path = file.is_absolute() ? file : (m_path / file);
        return std::filesystem::exists(file_path);
    }
}