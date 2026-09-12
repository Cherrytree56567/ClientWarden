#include "httplib.h"

namespace httplib {
    std::shared_ptr<Error> Client::Post(std::string url, Params headers, std::string value, std::string type, std::function<void(uint64_t, uint64_t)> onProgress) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        if (url.ends_with("/attachment/v2")) {
            err->body = "{\"cipherResponse\": {\"attachments\": []}, \"attachmentId\": \"att\"}";
        }

        g_h_data.url = url;
        g_h_data.params = headers;
        g_h_data.value = value;
        g_h_data.type = type;

        return err;
    }

    std::shared_ptr<Error> Client::Post(std::string url, Headers headers, std::string value, std::string type, std::function<void(uint64_t, uint64_t)> onProgress) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        if (url.ends_with("/attachment/v2")) {
            err->body = "{\"cipherResponse\": {\"attachments\": []}, \"attachmentId\": \"att\"}";
        }

        g_h_data.url = url;
        g_h_data.headers = headers;
        g_h_data.value = value;
        g_h_data.type = type;

        return err;
    }

    std::shared_ptr<Error> Client::Post(std::string url, Headers headers, UploadFormDataItems items, std::function<void(uint64_t, uint64_t)> onProgress) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        if (url.ends_with("/attachment/v2")) {
            err->body = "{\"cipherResponse\": {\"attachments\": []}, \"attachmentId\": \"att\"}";
        }

        g_h_data.url = url;
        g_h_data.headers = headers;
        g_h_data.items = items;

        return err;
    }

    std::shared_ptr<Error> Client::Put(std::string url, Headers headers, std::string value, std::string type) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        g_h_data.url = url;
        g_h_data.headers = headers;
        g_h_data.value = value;
        g_h_data.type = type;

        return err;
    }

    std::shared_ptr<Error> Client::Delete(std::string url, Headers headers) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        g_h_data.url = url;
        g_h_data.headers = headers;

        return err;
    }

    std::shared_ptr<Error> Client::Get(std::string url, Headers headers, std::function<void(uint64_t, uint64_t)> onProgress) {
        std::shared_ptr<Error> err = std::make_shared<Error>();

        std::regex pattern(R"(^/api/ciphers/[^/]+/attachment/[^/]+$)");
        if (std::regex_match(url, pattern)) {
            err->body = "{\"url\": \"att123\", \"fileName\": \"att.png\", \"key\": \"key123\"}";
        } else if (url == "att123") {
            std::string blob;
            blob += static_cast<char>(0x02);
            blob.append(16, static_cast<char>(0xAA));
            blob.append(32, static_cast<char>(0xBB));
            blob += "X";

            err->body = blob;
        }

        g_h_data.url = url;
        g_h_data.headers = headers;

        return err;
    }

    void Client::set_read_timeout(int timeout) {
        /*
         * STUB
        */
    }

    void Client::set_connection_timeout(int timeout) {
        /*
         * STUB
        */
    }

    void Client::set_default_headers(Headers headers) {
        g_h_data.headers = headers;
    }

    namespace ws {
        bool WebSocketClient::connect() {
            return true;
        }

        void WebSocketClient::send(std::string msg) {

        }
        
        void WebSocketClient::set_websocket_ping_interval(float num) {

        }

        void WebSocketClient::close(CloseStatus stat, std::string msg) {

        }

        bool WebSocketClient::read(std::string& msg) {
            msg = g_h_data.wsData;

            if (g_h_data.wsData != "{}\x1e") {
                g_h_data.wsData = "{}\x1e";
            }
            
            return g_h_data.runWS;
        }
    }
}