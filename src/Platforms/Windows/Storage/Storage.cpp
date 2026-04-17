#include "Storage.h"

Storage::Storage() {
    spdlog::set_pattern("[%H:%M:%S] [ClientWarden::Windows::Storage] [%^---%L---%$] [thread %t] %v");

    PWSTR path_tmp;

    /* 
     * Attempt to get user's AppData folder
     *
     * From Stack Overflow:
     * https://stackoverflow.com/questions/5920853/how-to-open-a-folder-in-appdata-with-c
     *
     * Microsoft Docs:
     * https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
     * https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
     */
    auto get_folder_path_ret = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path_tmp);

    if (get_folder_path_ret != S_OK) {
        CoTaskMemFree(path_tmp);
        spdlog::info("Failed to get AppData Path");
    }

    path = path_tmp;

    CoTaskMemFree(path_tmp);

    path.append("ClientWarden");

    /*
     * Create a Dir
     * https://en.cppreference.com/w/cpp/filesystem/create_directory.html
    */
    std::filesystem::create_directory(path);
}

Storage::Storage(std::string) {
    spdlog::set_pattern("[%H:%M:%S] [ClientWarden::Windows::Storage] [%^---%L---%$] [thread %t] %v");

    char buffer[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buffer, MAX_PATH);

    if (len == 0) {
        spdlog::info("Failed to get executable path");
        return;
    }

    std::filesystem::path Bufpath(buffer);

    path = Bufpath.parent_path();

    path.append("ClientWarden");
}

std::string Storage::read(std::filesystem::path file) {
    std::filesystem::path nFile = path / file;
    if (!std::filesystem::exists(nFile)) {
        spdlog::info("File not found: {}", nFile.string());
        throw std::runtime_error("File not found");
    }

    std::ifstream f(nFile, std::ios::in | std::ios::binary);
    if (!f) {
        spdlog::info("Failed to open file: {}", nFile.string());
        throw std::runtime_error("Failed to open file");
    }

    return std::string(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );
}

std::vector<uint8_t> Storage::readBinary(std::filesystem::path file) {
    std::filesystem::path nFile = path / file;
    if (!std::filesystem::exists(nFile)) {
        spdlog::info("File not found: {}", nFile.string());
        throw std::runtime_error("File not found");
    }

    auto size = std::filesystem::file_size(nFile);

    std::ifstream f(nFile, std::ios::binary);
    if (!f) {
        spdlog::info("Failed to open file: {}", nFile.string());
        throw std::runtime_error("Failed to open file");
    }

    std::vector<uint8_t> buffer(size);

    f.read(reinterpret_cast<char*>(buffer.data()), size);

    if (!f) {
        spdlog::info("Failed to read file: {}", nFile.string());
        throw std::runtime_error("Failed to read file");
    }

    return buffer;
}

void Storage::write(std::filesystem::path file, std::string data) {
    std::filesystem::path nFile = path / file;
    std::filesystem::create_directories(nFile.parent_path());

    std::ofstream f(nFile, std::ios::binary);
    if (!f) {
        spdlog::error("Failed to open file for writing: {}", nFile.string());
        throw std::runtime_error("Failed to open file for writing");
    }

    f.write(data.data(), data.size());

    if (!f) {
        spdlog::error("Failed to write file: {}", nFile.string());
        throw std::runtime_error("Failed to write file");
    }
}

void Storage::write(std::filesystem::path file, std::vector<uint8_t> data) {
    std::filesystem::path nFile = path / file;
    std::filesystem::create_directories(nFile.parent_path());

    std::ofstream f(nFile, std::ios::binary);
    if (!f) {
        spdlog::info("Failed to open file for writing: {}", nFile.string());
        throw std::runtime_error("Failed to open file for writing");
    }

    f.write(reinterpret_cast<const char*>(data.data()), data.size());

    if (!f) {
        spdlog::info("Failed to write file: {}", nFile.string());
        throw std::runtime_error("Failed to write file");
    }
}

void Storage::remove(std::filesystem::path file) {
    std::filesystem::path nFile = path / file;
    if (!std::filesystem::exists(nFile)) {
        return;
    }

    if (!std::filesystem::remove(nFile)) {
        spdlog::info("Failed to remove file: {}", nFile.string());
        throw std::runtime_error("Failed to remove file: " + nFile.string());
    }
}

void Storage::rename(std::filesystem::path file, std::string name) {
    std::filesystem::path nFile = path / file;
    if (!std::filesystem::exists(nFile)) {
        spdlog::info("File does not exist: {}", nFile.string());
        throw std::runtime_error("File does not exist: " + nFile.string());
    }

    std::filesystem::path newPath = nFile.parent_path() / name;

    std::filesystem::rename(nFile, newPath);
}

bool Storage::exists(std::filesystem::path file) {
    std::filesystem::path nFile = path / file;
    return std::filesystem::exists(nFile);
}