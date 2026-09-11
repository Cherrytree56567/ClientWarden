#pragma once
#include <string>
#include <map>
#include <functional>
#include <memory>

namespace httplib {

    using Headers = std::multimap<std::string, std::string>;

    struct Error {
        bool err = false;
        int status = 200;
        std::string body = "{}";

        bool operator!() const {
            return err; 
        }
    };

    /*
     * Avoiding the problem
     * plz fix at some point
    */
    struct Params : public std::multimap<std::string, std::string> {
        using std::multimap<std::string, std::string>::multimap;
    };

    struct UploadFormDataItem {
        std::string name;
        std::string content;
        std::string filename;
        std::string content_type;
    };

    using UploadFormDataItems = std::vector<UploadFormDataItem>;

    struct httplibData {
        Headers headers;
        Params params;
        UploadFormDataItems items;
        std::string url;
        std::string value;
        std::string type;
    };

    inline httplibData g_h_data = httplibData();

    class Client {
    public:
        Client(std::string baseURL) {}

        void set_default_headers(Headers headers);
        void set_connection_timeout(int timeout);
        void set_read_timeout(int timeout);

        std::shared_ptr<Error> Post(std::string url, Params headers, std::string value = "", std::string type = "", std::function<void(uint64_t, uint64_t)> onProgress = nullptr);
        std::shared_ptr<Error> Post(std::string url, Headers headers, std::string value = "", std::string type = "", std::function<void(uint64_t, uint64_t)> onProgress = nullptr);
        std::shared_ptr<Error> Post(std::string url, Headers headers, UploadFormDataItems items, std::function<void(uint64_t, uint64_t)> onProgress = nullptr);
        std::shared_ptr<Error> Put(std::string url, Headers headers, std::string value, std::string type);
        std::shared_ptr<Error> Delete(std::string url, Headers headers);
        std::shared_ptr<Error> Get(std::string url, Headers headers = Headers(), std::function<void(uint64_t, uint64_t)> onProgress = nullptr);
    };

    namespace ws {
        enum CloseStatus {
            GoingAway
        };

        class WebSocketClient {
        public:
            WebSocketClient(std::string url, Headers headers) {}

            bool connect();
            void send(std::string msg);
            void set_websocket_ping_interval(float num);
            void close(CloseStatus stat, std::string msg);
            bool read(std::string& msg);
        };
    }
}