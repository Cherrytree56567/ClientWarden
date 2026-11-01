#include "Storage.h"

Storage::Storage() {

}

Storage::Storage(std::string) {

}

std::string Storage::read(std::filesystem::path file) {
    return "";
}

std::vector<uint8_t> Storage::readBinary(std::filesystem::path file) {
    std::vector<uint8_t> buffer;

    return buffer;
}

void Storage::write(std::filesystem::path file, std::string data) {
}

void Storage::write(std::filesystem::path file, std::vector<uint8_t> data) {
}

void Storage::remove(std::filesystem::path file) {
}

void Storage::rename(std::filesystem::path file, std::string name) {
}

bool Storage::exists(std::filesystem::path file) {
    return false;
}