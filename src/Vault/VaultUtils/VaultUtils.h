#pragma once
#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <spdlog/spdlog.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid_generators.hpp>

std::string b64Encode(const std::vector<uint8_t>& data); // Claude Func
std::vector<uint8_t> b64Decode(const std::string& data); // Claude Func
std::time_t BitwardenTime(std::string time);
std::string getBitwardenTime();
std::string uniqueGuid();