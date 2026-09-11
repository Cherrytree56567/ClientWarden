#include "httplib.h"

namespace httplib {
    Error Client::Post(std::string url, Headers, std::string value, std::string type) {
        Error err;
        if (url.ends_with("/attachment/v2")) {
            err->body = '{
                "cipherResponse": {
                    "attachments": [] 
                },
                "attachmentId": ""
            }';
        }
    }
}