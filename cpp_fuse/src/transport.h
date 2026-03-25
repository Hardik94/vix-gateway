#pragma once
#include <string>

struct Http3ClientConfig {
    std::string host;
    int port{9443};
    std::string token; // optional bearer token
    // Optional: when talking to control server as LB, include x-client-id
    std::string client_id;
};

// Returns true on success and fills json_out
bool h3_post_json(const Http3ClientConfig& cfg, const std::string& path, const std::string& json_in, std::string& json_out);
bool h3_get_json(const Http3ClientConfig& cfg, const std::string& path, std::string& json_out);

// Binary (octet-stream) helpers
bool h3_get_bytes(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes);
bool h3_post_bytes(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes);

// Protobuf (application/x-protobuf) helpers
bool h3_get_proto(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes);
bool h3_post_proto(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes);


