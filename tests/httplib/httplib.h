#pragma once
#include <string>

namespace httplib {
    using Headers = std::multimap<std::string, std::string>;

    struct Error {
        bool err = false;
        int status = 200;
        std::string body = "";

        bool operator!() const {
            return !err; 
        }
    };

    class Client {
        Error Post(std::string url, Headers, std::string value, std::string type);
    };
}