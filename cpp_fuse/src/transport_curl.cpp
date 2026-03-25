#include "transport.h"
#include <curl/curl.h>
#include <string>

static size_t write_to_string(void *ptr, size_t size, size_t nmemb, void *userdata) {
    std::string *out = static_cast<std::string*>(userdata);
    out->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

static bool curl_request(const Http3ClientConfig& cfg, const std::string& method, const std::string& path, const std::string& json_in, std::string& json_out) {
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    std::string url = "https://" + cfg.host + ":" + std::to_string(cfg.port) + path;
    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    if (!cfg.token.empty()) {
        std::string auth = std::string("Authorization: Bearer ") + cfg.token;
        hdrs = curl_slist_append(hdrs, auth.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json_out);
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_in.c_str());
    }
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) && (code >= 200 && code < 300);
}

bool h3_post_json(const Http3ClientConfig& cfg, const std::string& path, const std::string& json_in, std::string& json_out) {
    return curl_request(cfg, "POST", path, json_in, json_out);
}

bool h3_get_json(const Http3ClientConfig& cfg, const std::string& path, std::string& json_out) {
    std::string empty;
    return curl_request(cfg, "GET", path, empty, json_out);
}

static bool curl_request_bytes(const Http3ClientConfig& cfg, const std::string& method, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    std::string url = "https://" + cfg.host + ":" + std::to_string(cfg.port) + path;
    struct curl_slist *hdrs = nullptr;
    // Accept raw bytes
    hdrs = curl_slist_append(hdrs, "Accept: application/octet-stream");
    if (!cfg.token.empty()) {
        std::string auth = std::string("Authorization: Bearer ") + cfg.token;
        hdrs = curl_slist_append(hdrs, auth.c_str());
    }
    if (method == "POST") {
        hdrs = curl_slist_append(hdrs, "Content-Type: application/octet-stream");
    }
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out_bytes);
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in_bytes.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)in_bytes.size());
    }
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) && (code >= 200 && code < 300);
}

bool h3_get_bytes(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes) {
    std::string empty;
    return curl_request_bytes(cfg, "GET", path, empty, out_bytes);
}

bool h3_post_bytes(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    return curl_request_bytes(cfg, "POST", path, in_bytes, out_bytes);
}

static bool curl_request_proto(const Http3ClientConfig& cfg, const std::string& method, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    std::string url = "https://" + cfg.host + ":" + std::to_string(cfg.port) + path;
    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Accept: application/x-protobuf");
    if (method == "POST") hdrs = curl_slist_append(hdrs, "Content-Type: application/x-protobuf");
    if (!cfg.token.empty()) {
        std::string auth = std::string("Authorization: Bearer ") + cfg.token;
        hdrs = curl_slist_append(hdrs, auth.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out_bytes);
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, in_bytes.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)in_bytes.size());
    }
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) && (code >= 200 && code < 300);
}

bool h3_get_proto(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes) {
    std::string empty;
    return curl_request_proto(cfg, "GET", path, empty, out_bytes);
}

bool h3_post_proto(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    return curl_request_proto(cfg, "POST", path, in_bytes, out_bytes);
}


