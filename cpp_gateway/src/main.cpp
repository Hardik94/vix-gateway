#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <inttypes.h>

extern "C" {
#include <quiche.h>
#if defined(__has_include)
#  if __has_include(<quiche_h3.h>)
#    include <quiche_h3.h>
#  elif __has_include(<quiche/h3.h>)
#    include <quiche/h3.h>
#  endif
#endif
}

#ifdef PROTOBUF_AVAILABLE
#include "fs.pb.h"
#endif

static bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

struct Args {
    std::string host = "0.0.0.0";
    int port = 9443;
    std::filesystem::path storage = "./quic_s3_storage";
    std::filesystem::path cert = "./quic_cert.pem";
    std::filesystem::path key = "./quic_key.pem";
    bool flat = false;
    bool durable = false;
    int read_ahead = 256 * 1024;
    bool verbose = false;
    std::string token;  // if set, require Authorization: Bearer <token>
    // Control-plane integration (optional)
    bool enable_control{false};
    std::string control_host;
    int control_port{9444};
    std::string client_id;
    std::string remote{"quic://auto"};
    std::string public_host;
    int public_port{0};
};

static void print_usage(const char* prog) {
    std::cout <<
        "Usage: " << prog << " [options]\n"
        "  --host HOST                 Listen address (default 0.0.0.0)\n"
        "  --port PORT                 Listen port (default 9443)\n"
        "  --storage DIR               Storage root directory\n"
        "  --cert PATH                 TLS certificate (PEM)\n"
        "  --key PATH                  TLS private key (PEM)\n"
        "  --flat                      Operate directly on storage root (no buckets)\n"
        "  --durable-writes            fsync after writes (slower, safer)\n"
        "  --read-ahead-bytes N        Read-ahead base for /fs/read (default 262144)\n"
        "  --token TOKEN               Require Authorization: Bearer TOKEN\n"
        "  --enable-control            Register and mount with control server\n"
        "  --control-host HOST         Control server host\n"
        "  --control-port PORT         Control server port (default 9444)\n"
        "  --client-id ID              Client ID to register at control\n"
        "  --remote URL                Advertised URL (default quic://auto)\n"
        "  --public-host HOST          Override advertised host when --remote=quic://auto\n"
        "  --public-port PORT          Override advertised port when --remote=quic://auto\n"
        "  --verbose, -v               Verbose request/response logging\n"
        "  --help, -h                  Show this help\n";
}

static std::string json_encode(const std::string &k, const std::string &v) {
    std::ostringstream oss;
    oss << "{\"" << k << "\":\"" << v << "\"}";
    return oss.str();
}

static std::string json_encode_kv(const std::vector<std::pair<std::string, std::string>>& kv) {
    std::ostringstream oss;
    oss << "{";
    for (size_t i = 0; i < kv.size(); ++i) {
        if (i) oss << ",";
        oss << "\"" << kv[i].first << "\":";
        bool needs_quotes = true;
        for (auto c : kv[i].second) {
            if (!(std::isdigit(c) || c == '.')) { needs_quotes = true; break; }
        }
        oss << "\"" << kv[i].second << "\"";
    }
    oss << "}";
    return oss.str();
}

static std::string detect_primary_ipv4() {
    std::string ip = "127.0.0.1";
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return ip;
    struct sockaddr_in serv{}; serv.sin_family = AF_INET; serv.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);
    (void)connect(fd, (struct sockaddr*)&serv, sizeof(serv));
    struct sockaddr_in name{}; socklen_t namelen = sizeof(name);
    if (getsockname(fd, (struct sockaddr*)&name, &namelen) == 0) {
        char buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf))) ip = buf;
    }
    close(fd);
    return ip;
}

static void compute_advertised_endpoint(const Args& a, std::string& out_host, int& out_port) {
    out_port = (a.public_port > 0 ? a.public_port : a.port);
    if (!a.public_host.empty()) { out_host = a.public_host; return; }
    // If bound to wildcard or loopback, pick primary
    if (a.host == "0.0.0.0" || a.host == "::" || a.host == "127.0.0.1" || a.host == "::1") {
        out_host = detect_primary_ipv4();
    } else {
        out_host = a.host;
    }
}

// Minimal HTTP/3 client for JSON POST/GET to control server
static bool h3_control_request_json(const std::string& host, int port, const std::string& method, const std::string& path, const std::string& body, std::string& out_json) {
    out_json.clear();
    // Resolve peer
    struct addrinfo hints; std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo* res = nullptr;
    std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &res) != 0 || !res) return false;
    int sockfd = -1; struct addrinfo* rp = res;
    for (; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd >= 0) break;
    }
    if (sockfd < 0) { freeaddrinfo(res); return false; }
    set_nonblocking(sockfd);
    sockaddr_storage local{}; socklen_t local_len = 0;
    if (rp->ai_family == AF_INET6) {
        struct sockaddr_in6 l{}; l.sin6_family = AF_INET6;
        bind(sockfd, (struct sockaddr*)&l, sizeof(l)); local_len = sizeof(l); std::memcpy(&local, &l, sizeof(l));
    } else {
        struct sockaddr_in l{}; l.sin_family = AF_INET;
        bind(sockfd, (struct sockaddr*)&l, sizeof(l)); local_len = sizeof(l); std::memcpy(&local, &l, sizeof(l));
    }
    quiche_config* qcfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    const uint8_t alpn[] = {
        0x05, 'h','3','-','2','9',
        0x05, 'h','3','-','3','0',
        0x05, 'h','3','-','3','1',
        0x05, 'h','3','-','3','2',
        0x02, 'h', '3'
    };
    quiche_config_set_application_protos(qcfg, alpn, sizeof(alpn));
    quiche_config_verify_peer(qcfg, false);
    uint8_t scid[16]; for (auto &b : scid) b = (uint8_t)(rand() & 0xff);
    quiche_conn* conn = quiche_connect((const char*)host.c_str(), scid, sizeof(scid),
                                       (sockaddr*)&local, local_len,
                                       (sockaddr*)rp->ai_addr, (socklen_t)rp->ai_addrlen, qcfg);
    if (!conn) { quiche_config_free(qcfg); freeaddrinfo(res); close(sockfd); return false; }
    // Drive handshake
    std::vector<uint8_t> io(1350);
    quiche_send_info sinfo{}; sinfo.to_len = (socklen_t)rp->ai_addrlen; std::memcpy(&sinfo.to, rp->ai_addr, rp->ai_addrlen);
    sinfo.from = local; sinfo.from_len = local_len;
    for (int i = 0; i < 200 && !quiche_conn_is_established(conn); ++i) {
        while (true) {
            ssize_t written = quiche_conn_send(conn, io.data(), io.size(), &sinfo);
            if (written == QUICHE_ERR_DONE) break;
            if (written < 0) break;
            (void)sendto(sockfd, io.data(), (size_t)written, 0, (sockaddr*)rp->ai_addr, (socklen_t)rp->ai_addrlen);
        }
        uint8_t recv_buf[65536];
        struct pollfd pfd{ sockfd, POLLIN, 0 };
        (void)poll(&pfd, 1, 20);
        sockaddr_storage from{}; socklen_t from_len = sizeof(from);
        ssize_t read = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&from, &from_len);
        if (read > 0) {
            quiche_recv_info rinfo{}; rinfo.from = (sockaddr*)&from; rinfo.from_len = from_len; rinfo.to = (sockaddr*)&local; rinfo.to_len = local_len;
            (void)quiche_conn_recv(conn, recv_buf, (size_t)read, &rinfo);
        }
    }
    if (!quiche_conn_is_established(conn)) { quiche_conn_free(conn); quiche_config_free(qcfg); freeaddrinfo(res); close(sockfd); return false; }
    quiche_h3_config* h3cfg = quiche_h3_config_new();
    quiche_h3_config_set_max_field_section_size(h3cfg, 16 * 1024);
    quiche_h3_config_set_qpack_max_table_capacity(h3cfg, 0);
    quiche_h3_config_set_qpack_blocked_streams(h3cfg, 0);
    quiche_h3_conn* h3 = quiche_h3_conn_new_with_transport(conn, h3cfg);
    if (!h3) { quiche_conn_free(conn); quiche_h3_config_free(h3cfg); quiche_config_free(qcfg); freeaddrinfo(res); close(sockfd); return false; }
    // Build headers
    std::string authority = host + ":" + std::to_string(port);
    std::vector<quiche_h3_header> hdrs;
    // Storage to keep header strings alive until after send_request
    std::vector<std::string> hdr_name_store;
    std::vector<std::string> hdr_value_store;
    hdr_name_store.reserve(8);
    hdr_value_store.reserve(8);
    auto push_hdr = [&](const std::string& name, const std::string& value){
        hdr_name_store.emplace_back(name);
        hdr_value_store.emplace_back(value);
        quiche_h3_header h;
        h.name = (uint8_t*)hdr_name_store.back().c_str();
        h.name_len = hdr_name_store.back().size();
        h.value = (uint8_t*)hdr_value_store.back().c_str();
        h.value_len = hdr_value_store.back().size();
        hdrs.push_back(h);
    };
    push_hdr(":method", std::string(method));
    push_hdr(":scheme", std::string("https"));
    push_hdr(":authority", authority);
    push_hdr(":path", path);
    push_hdr("user-agent", std::string("vix-cpp-gateway/0.1"));
    push_hdr("content-type", std::string("application/json"));
    int64_t sid = quiche_h3_send_request(h3, conn, hdrs.data(), hdrs.size(), body.empty());
    if (!body.empty()) {
        const uint8_t* data = (const uint8_t*)body.data();
        size_t total = body.size();
        size_t sent = 0;
        while (sent < total) {
            size_t chunk = std::min((size_t)8 * 1024, total - sent);
            ssize_t r = quiche_h3_send_body(h3, conn, (uint64_t)sid, data + sent, chunk, (sent + chunk) == total);
            if (r == QUICHE_H3_ERR_BUFFER_TOO_SHORT || r == QUICHE_ERR_DONE) {
                // drive IO
            } else if (r < 0) {
                break;
            } else {
                sent += (size_t)r;
            }
            // Flush
            while (true) {
                ssize_t written = quiche_conn_send(conn, io.data(), io.size(), &sinfo);
                if (written == QUICHE_ERR_DONE) break;
                if (written < 0) break;
                (void)sendto(sockfd, io.data(), (size_t)written, 0, (sockaddr*)rp->ai_addr, (socklen_t)rp->ai_addrlen);
            }
        }
    } else {
        // Just flush headers
        while (true) {
            ssize_t written = quiche_conn_send(conn, io.data(), io.size(), &sinfo);
            if (written == QUICHE_ERR_DONE) break;
            if (written < 0) break;
            (void)sendto(sockfd, io.data(), (size_t)written, 0, (sockaddr*)rp->ai_addr, (socklen_t)rp->ai_addrlen);
        }
    }
    bool done = false;
    std::string payload;
    for (int it = 0; it < 300 && !done; ++it) {
        uint8_t recv_buf[65536];
        struct pollfd pfd{ sockfd, POLLIN, 0 };
        (void)poll(&pfd, 1, 20);
        sockaddr_storage from{}; socklen_t from_len = sizeof(from);
        ssize_t read = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&from, &from_len);
        if (read > 0) {
            quiche_recv_info rinfo{}; rinfo.from = (sockaddr*)&from; rinfo.from_len = from_len; rinfo.to = (sockaddr*)&local; rinfo.to_len = local_len;
            (void)quiche_conn_recv(conn, recv_buf, (size_t)read, &rinfo);
        }
        while (true) {
            quiche_h3_event* ev = nullptr;
            int64_t esid = quiche_h3_conn_poll(h3, conn, &ev);
            if (esid < 0) break;
            int t = quiche_h3_event_type(ev);
            if (t == QUICHE_H3_EVENT_DATA) {
                uint8_t b[16*1024];
                while (true) {
                    ssize_t n = quiche_h3_recv_body(h3, conn, (uint64_t)esid, b, sizeof(b));
                    if (n == QUICHE_H3_ERR_DONE || n == QUICHE_H3_ERR_BUFFER_TOO_SHORT) break;
                    if (n < 0) break;
                    payload.append((const char*)b, (size_t)n);
                }
            } else if (t == QUICHE_H3_EVENT_FINISHED) {
                done = true;
            }
            quiche_h3_event_free(ev);
        }
        // Flush outstanding
        while (true) {
            ssize_t written = quiche_conn_send(conn, io.data(), io.size(), &sinfo);
            if (written == QUICHE_ERR_DONE) break;
            if (written < 0) break;
            (void)sendto(sockfd, io.data(), (size_t)written, 0, (sockaddr*)rp->ai_addr, (socklen_t)rp->ai_addrlen);
        }
    }
    out_json = payload;
    quiche_h3_conn_free(h3);
    quiche_h3_config_free(h3cfg);
    quiche_conn_free(conn);
    quiche_config_free(qcfg);
    freeaddrinfo(res);
    close(sockfd);
    return !out_json.empty();
}

static void control_register_and_mount_async(Args a) {
    if (!a.enable_control || a.control_host.empty() || a.client_id.empty()) return;
    std::string adv_host; int adv_port = 0;
    std::string remote_url = a.remote;
    if (remote_url == "quic://auto" || remote_url == "https://auto") {
        compute_advertised_endpoint(a, adv_host, adv_port);
        remote_url = std::string("quic://") + adv_host + ":" + std::to_string(adv_port);
    }
    std::cout << "[gateway-cpp] control: advertising " << remote_url << " as " << a.client_id << "\n";
    // /register
    std::string reg_body = json_encode_kv({{"client_id", a.client_id}, {"token", a.token}});
    std::string reg_resp;
    (void)h3_control_request_json(a.control_host, a.control_port, "POST", "/register", reg_body, reg_resp);
    std::cout << "[gateway-cpp] control: register => " << (reg_resp.empty() ? "(no body)" : reg_resp) << "\n";
    // /mount
    std::string m_body = json_encode_kv({{"client_id", a.client_id}, {"remote", remote_url}, {"export", "/"}});
    std::string m_resp;
    (void)h3_control_request_json(a.control_host, a.control_port, "POST", "/mount", m_body, m_resp);
    std::cout << "[gateway-cpp] control: mount => " << (m_resp.empty() ? "(no body)" : m_resp) << "\n";
}

struct Conn {
    sockaddr_storage peer{};
    socklen_t peer_len{0};
    sockaddr_storage local{};
    socklen_t local_len{0};
    quiche_conn* q{nullptr};
    quiche_h3_config* h3cfg{nullptr};
    quiche_h3_conn* h3{nullptr};
    std::chrono::steady_clock::time_point last_tick{};
    struct ReqCtx {
        std::string method;
        std::string path;
        std::string content_type;
        std::string body;
        std::string accept;
        std::string authorization;
        std::string client_id;
    };
    std::unordered_map<uint64_t, ReqCtx> reqs;
};

static int make_udp_socket(const std::string& host, int port, sockaddr_storage &local, socklen_t &local_len) {
    std::string service = std::to_string(port);
    struct addrinfo hints; std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (rc != 0) return -1;
    int fd = -1;
    for (auto p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int on = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (bind(fd, p->ai_addr, p->ai_addrlen) < 0) { close(fd); fd = -1; continue; }
        std::memcpy(&local, p->ai_addr, p->ai_addrlen);
        local_len = (socklen_t)p->ai_addrlen;
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static void add_fc_windows(quiche_config* cfg) {
    quiche_config_set_initial_max_data(cfg, 128 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_bidi_local(cfg, 32 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_bidi_remote(cfg, 32 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_uni(cfg, 1 * 1024 * 1024);
    quiche_config_set_initial_max_streams_bidi(cfg, 1024);
    quiche_config_set_initial_max_streams_uni(cfg, 256);
    // quiche_config_set_initial_max_streams_bidi(cfg, 10);
    // quiche_config_set_initial_max_streams_uni(cfg, 5);
}

struct Server {
    int sock{-1};
    sockaddr_storage local{}; socklen_t local_len{0};
    quiche_config* qcfg{nullptr};
    std::unordered_map<std::string, Conn> conns;
    Args args;
};

static std::string peer_key(const sockaddr_storage& ss, socklen_t len) {
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo((const sockaddr*)&ss, len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return "";
    }
    return std::string(host) + ":" + std::string(serv);
}

static void send_h3_json(Conn& c, uint64_t stream_id, int status, const std::string& body) {
    std::vector<quiche_h3_header> hdrs;
    auto push = [&](const char* n, const char* v) {
        quiche_h3_header h; h.name=(uint8_t*)n; h.name_len=std::strlen(n); h.value=(uint8_t*)v; h.value_len=std::strlen(v); hdrs.push_back(h);
    };
    std::string st = std::to_string(status);
    push(":status", st.c_str());
    push("server", "vix-gateway/0.1");
    push("content-type", "application/json");
    quiche_h3_send_response(c.h3, c.q, stream_id, hdrs.data(), hdrs.size(), false);
    quiche_h3_send_body(c.h3, c.q, stream_id, (const uint8_t*)body.data(), body.size(), true);
    std::cout << "[gateway-cpp] -> JSON sid=" << stream_id << " status=" << status << " bytes=" << body.size() << "\n";
}

#ifdef PROTOBUF_AVAILABLE
static void send_h3_proto(Conn& c, uint64_t stream_id, const std::string& bytes) {
    std::vector<quiche_h3_header> hdrs;
    auto push = [&](const char* n, const char* v) {
        quiche_h3_header h; h.name=(uint8_t*)n; h.name_len=std::strlen(n); h.value=(uint8_t*)v; h.value_len=std::strlen(v); hdrs.push_back(h);
    };
    push(":status", "200");
    push("server", "vix-gateway/0.1");
    push("content-type", "application/x-protobuf");
    quiche_h3_send_response(c.h3, c.q, stream_id, hdrs.data(), hdrs.size(), false);
    quiche_h3_send_body(c.h3, c.q, stream_id, (const uint8_t*)bytes.data(), bytes.size(), true);
    std::cout << "[gateway-cpp] -> PROTO sid=" << stream_id << " status=200 bytes=" << bytes.size() << "\n";
}
#endif

static std::string read_file_region(const std::filesystem::path& p, int64_t offset, int64_t size) {
    std::ifstream f(p, std::ios::binary);
    if (!f.good()) return {};
    if (offset > 0) f.seekg(offset);
    std::ostringstream oss;
    if (size > 0) {
        std::vector<char> buf((size_t)size);
        f.read(buf.data(), (std::streamsize)size);
        oss.write(buf.data(), f.gcount());
    } else {
        oss << f.rdbuf();
    }
    return oss.str();
}

static void h3_route(Server& s, Conn& c, uint64_t stream_id, const std::string& method, const std::string& path, const std::string& content_type, const std::string& body) {
    if (s.args.verbose) {
        std::cout << "[gateway-cpp] route sid=" << stream_id << " method=" << method << " path=" << path
                  << " ctype=" << (content_type.empty()?"":content_type) << " body=" << body.size() << "\n";
    }
    // crude parsing of query
    auto pos_q = path.find('?');
    std::string pth = pos_q == std::string::npos ? path : path.substr(0, pos_q);
    std::unordered_map<std::string, std::string> query;
    if (pos_q != std::string::npos) {
        auto q = path.substr(pos_q + 1);
        std::istringstream iss(q);
        std::string kv;
        while (std::getline(iss, kv, '&')) {
            auto eq = kv.find('=');
            if (eq != std::string::npos) query[kv.substr(0, eq)] = kv.substr(eq + 1);
        }
    }
    auto root = std::filesystem::weakly_canonical(s.args.storage);
    auto clamp = [&](const std::string& rel_in)->std::filesystem::path{
        if (rel_in.empty() || rel_in == "/" || rel_in == "." || rel_in == "..") return root;
        auto rel = rel_in[0] == '/' ? rel_in.substr(1) : rel_in;
        auto candidate = std::filesystem::weakly_canonical(root / rel);
        std::error_code ec;
        auto common = std::filesystem::weakly_canonical(root, ec);
        if (ec) return root;
        auto cand_str = candidate.string();
        auto root_str = common.string();
        if (cand_str.rfind(root_str, 0) != 0) return root; // not under root
        return candidate;
    };

    if (method == "GET" && pth == "/health") {
        send_h3_json(c, stream_id, 200, "{\"ok\":true}");
        return;
    }

    if (method == "POST" && pth == "/fs/unlink") {
        // JSON: {"path":"..."}
        std::string rel;
        if (!body.empty()) {
            auto p1 = body.find("\"path\"");
            if (p1 != std::string::npos) {
                auto q1 = body.find('"', body.find(':', p1) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) rel = body.substr(q1 + 1, q2 - q1 - 1);
            }
        }
        auto target = clamp(rel);
        std::error_code ec;
        if (!std::filesystem::exists(target, ec) || !std::filesystem::is_regular_file(target, ec)) {
            send_h3_json(c, stream_id, 404, json_encode("error","not a file")); return;
        }
        std::filesystem::remove(target, ec);
        if (ec) {
            send_h3_json(c, stream_id, 500, json_encode("error","unlink failed")); return;
        }
        // fsync directory for durability
        int dfd = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
        if (s.args.verbose) {
            std::cout << "[gateway-cpp] unlink target=" << target << "\n";
        }
        send_h3_json(c, stream_id, 200, "{\"ok\":true}");
        return;
    }

    if ((method == "GET" || method == "POST") && pth == "/fs/stat") {
        // Honor requested path; default to "/"
        std::string rel = (method == "GET") ? (query.count("path") ? query["path"] : "/") : "/";
        if (method == "POST" && !body.empty()) {
            auto pos = body.find("\"path\"");
            if (pos != std::string::npos) {
                auto q1 = body.find('"', body.find(':', pos) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) rel = body.substr(q1 + 1, q2 - q1 - 1);
            }
        }
        auto target = clamp(rel);
        std::error_code ec;
        auto st = std::filesystem::status(target, ec);
        if (ec || !std::filesystem::exists(st)) {
            send_h3_json(c, stream_id, 404, json_encode("error","not found")); return;
        }
        auto is_dir = std::filesystem::is_directory(st);
        auto is_file = std::filesystem::is_regular_file(st);
        uintmax_t fsize = is_file ? std::filesystem::file_size(target, ec) : 0;
#ifdef PROTOBUF_AVAILABLE
        if (c.reqs[stream_id].accept == "application/x-protobuf") {
            struct stat stpos{}; ::stat(target.c_str(), &stpos);
            vix::fs::FsStatResponse resp;
            resp.set_path(rel);
            resp.set_is_dir(is_dir);
            resp.set_is_file(is_file);
            resp.set_mode((uint64_t)stpos.st_mode);
            resp.set_size((uint64_t)fsize);
            resp.set_mtime((int64_t)stpos.st_mtime);
            resp.set_ctime((int64_t)stpos.st_ctime);
            resp.set_uid((uint32_t)stpos.st_uid);
            resp.set_gid((uint32_t)stpos.st_gid);
            std::string bytes; resp.SerializeToString(&bytes);
            send_h3_proto(c, stream_id, bytes);
        } else
#endif
        {
            std::ostringstream oss;
            oss << "{"
                << "\"path\":\"" << rel << "\","
                << "\"is_dir\":" << (is_dir ? "true" : "false") << ","
                << "\"is_file\":" << (is_file ? "true" : "false") << ","
                << "\"size\":" << fsize
                << "}";
        if (s.args.verbose) {
            std::cout << "[gateway-cpp] stat target=" << target << " is_dir=" << (is_dir?"1":"0") << " size=" << fsize << "\n";
        }
            send_h3_json(c, stream_id, 200, oss.str());
        }
        return;
    }

    if ((method == "GET" || method == "POST") && pth == "/fs/readdir") {
        // Honor requested path; default to "/"
        std::string rel = (method == "GET") ? (query.count("path") ? query["path"] : "/") : "/";
        if (method == "POST" && !body.empty()) {
            auto pos = body.find("\"path\"");
            if (pos != std::string::npos) {
                auto q1 = body.find('"', body.find(':', pos) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) rel = body.substr(q1 + 1, q2 - q1 - 1);
            }
        }
        auto target = clamp(rel);
        std::error_code ec;
        if (!std::filesystem::exists(target, ec) || !std::filesystem::is_directory(target, ec)) {
            send_h3_json(c, stream_id, 404, json_encode("error","not a directory")); return;
        }
        bool accept_pb =
#ifdef PROTOBUF_AVAILABLE
            (c.reqs[stream_id].accept == "application/x-protobuf");
#else
            false;
#endif
        if (accept_pb) {
#ifdef PROTOBUF_AVAILABLE
            vix::fs::FsReaddirResponse resp;
            for (auto &entry : std::filesystem::directory_iterator(target)) {
                auto name = entry.path().filename().string();
                auto is_dir = entry.is_directory();
                auto is_file = entry.is_regular_file();
                uintmax_t size = 0;
                std::error_code ec2;
                if (is_file) size = std::filesystem::file_size(entry, ec2);
                struct stat stpos{}; ::stat(entry.path().c_str(), &stpos);
                auto *e = resp.add_entries();
                e->set_name(name);
                e->set_is_dir(is_dir);
                e->set_is_file(is_file);
                e->set_size((uint64_t)size);
                e->set_mode((uint64_t)stpos.st_mode);
                e->set_mtime((int64_t)stpos.st_mtime);
            }
            std::string bytes; resp.SerializeToString(&bytes);
            send_h3_proto(c, stream_id, bytes);
#endif
        } else {
            std::ostringstream oss; oss << "{\"entries\":[";
            bool first = true;
            for (auto &entry : std::filesystem::directory_iterator(target)) {
                if (!first) oss << ",";
                first = false;
                auto name = entry.path().filename().string();
                auto is_dir = entry.is_directory();
                auto is_file = entry.is_regular_file();
                uintmax_t size = 0;
                if (is_file) {
                    std::error_code ec2;
                    size = std::filesystem::file_size(entry, ec2);
                }
                oss << "{\"name\":\"" << name << "\",\"is_dir\":" << (is_dir?"true":"false") << ",\"is_file\":" << (is_file?"true":"false") << ",\"size\":" << size << "}";
            }
            oss << "]}";
            if (s.args.verbose) {
                std::cout << "[gateway-cpp] readdir target=" << target << "\n";
            }
            send_h3_json(c, stream_id, 200, oss.str());
        }
        return;
    }

    if (method == "GET" && pth == "/fs/read") {
        auto rel = query.count("path") ? query["path"] : "";
        int64_t offset = query.count("offset") ? std::stoll(query["offset"]) : 0;
        int64_t size = query.count("size") ? std::stoll(query["size"]) : 0;
        auto target = clamp(rel);
        std::error_code ec;
        if (!std::filesystem::exists(target, ec) || !std::filesystem::is_regular_file(target, ec)) {
            send_h3_json(c, stream_id, 404, json_encode("error","not a file")); return;
        }
        auto data = read_file_region(target, offset, size);
        // Octet-stream
        std::vector<quiche_h3_header> hdrs;
        auto push = [&](const char* n, const char* v) {
            quiche_h3_header h; h.name=(uint8_t*)n; h.name_len=std::strlen(n); h.value=(uint8_t*)v; h.value_len=std::strlen(v); hdrs.push_back(h);
        };
        push(":status", "200");
        push("server", "vix-gateway/0.1");
        push("content-type", "application/octet-stream");
        quiche_h3_send_response(c.h3, c.q, stream_id, hdrs.data(), hdrs.size(), false);
        quiche_h3_send_body(c.h3, c.q, stream_id, (const uint8_t*)data.data(), data.size(), true);
        if (s.args.verbose) {
            std::cout << "[gateway-cpp] read target=" << target << " offset=" << offset << " size_req=" << size << " size_out=" << data.size() << "\n";
        }
        return;
    }

    if (method == "POST" && pth == "/fs/write") {
        // application/octet-stream with path,offset in query
        auto rel = query.count("path") ? query["path"] : "";
        int64_t offset = query.count("offset") ? std::stoll(query["offset"]) : 0;
        auto target = clamp(rel);
        std::error_code ec;
        std::filesystem::create_directories(target.parent_path(), ec);
        std::fstream f;
        f.open(target, std::ios::in | std::ios::out | std::ios::binary);
        if (!f.is_open()) {
            f.clear();
            f.open(target, std::ios::out | std::ios::binary | std::ios::trunc);
            f.close();
            f.open(target, std::ios::in | std::ios::out | std::ios::binary);
        }
        if (!f.is_open()) {
            send_h3_json(c, stream_id, 500, json_encode("error","open failed")); return;
        }
        if (offset > 0) f.seekp(offset);
        f.write(body.data(), (std::streamsize)body.size());
        f.flush();
        if (s.args.durable) {
            int fd = ::open(target.c_str(), O_RDONLY);
            if (fd >= 0) { fsync(fd); close(fd); }
            int dfd = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
            if (dfd >= 0) { fsync(dfd); close(dfd); }
        }
        if (s.args.verbose) {
            std::cout << "[gateway-cpp] write target=" << target << " offset=" << offset << " written=" << body.size() << "\n";
        }
        std::ostringstream oss; oss << "{\"ok\":true,\"written\":" << body.size() << "}";
        send_h3_json(c, stream_id, 200, oss.str());
        return;
    }

    if (method == "POST" && pth == "/fs/truncate") {
        // JSON: {"path":"...", "size":N}
        std::string rel; int64_t size = 0;
        if (!body.empty()) {
            auto p1 = body.find("\"path\"");
            if (p1 != std::string::npos) {
                auto q1 = body.find('"', body.find(':', p1) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) rel = body.substr(q1 + 1, q2 - q1 - 1);
            }
            auto p2 = body.find("\"size\"");
            if (p2 != std::string::npos) {
                auto c = body.find(':', p2);
                if (c != std::string::npos) size = std::stoll(body.substr(c + 1));
            }
        }
        auto target = clamp(rel);
        std::error_code ec;
        std::filesystem::create_directories(target.parent_path(), ec);
        {
            std::fstream f(target, std::ios::in | std::ios::out | std::ios::binary);
            if (!f.is_open()) {
                f.clear();
                f.open(target, std::ios::out | std::ios::binary | std::ios::trunc);
                f.close();
                f.open(target, std::ios::in | std::ios::out | std::ios::binary);
            }
            if (!f.is_open()) { send_h3_json(c, stream_id, 500, json_encode("error","open failed")); return; }
            f.seekp(size);
            ::truncate(target.c_str(), size);
            f.flush();
        }
        int dfd = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
        std::cout << "[gateway-cpp] truncate target=" << target << " size=" << size << "\n";
        send_h3_json(c, stream_id, 200, "{\"ok\":true}");
        return;
    }

    if ((method == "GET" || method == "POST") && pth == "/fs/statfs") {
        // Honor requested path; default to "/"
        std::string rel = (method == "GET") ? (query.count("path") ? query["path"] : "/") : "/";
        if (method == "POST" && !body.empty()) {
            auto pos = body.find("\"path\"");
            if (pos != std::string::npos) {
                auto q1 = body.find('"', body.find(':', pos) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) rel = body.substr(q1 + 1, q2 - q1 - 1);
            }
        }
        auto target = clamp(rel);
        // If target does not exist, fall back to storage root
        std::error_code ec_exist;
        if (!std::filesystem::exists(target, ec_exist)) {
            target = root;
        }
        struct statvfs v{};
        if (statvfs(target.c_str(), &v) != 0) {
            send_h3_json(c, stream_id, 500, json_encode("error","statvfs failed")); return;
        }
        bool accept_pb =
#ifdef PROTOBUF_AVAILABLE
            (c.reqs[stream_id].accept == "application/x-protobuf");
#else
            false;
#endif
        if (accept_pb) {
#ifdef PROTOBUF_AVAILABLE
            vix::fs::FsStatfsResponse resp;
            resp.set_f_bsize(v.f_bsize);
            resp.set_f_frsize(v.f_frsize);
            resp.set_f_blocks(v.f_blocks);
            resp.set_f_bfree(v.f_bfree);
            resp.set_f_bavail(v.f_bavail);
            resp.set_f_files(v.f_files);
            resp.set_f_ffree(v.f_ffree);
            resp.set_f_favail(v.f_favail);
            resp.set_f_namemax(v.f_namemax);
            std::string bytes; resp.SerializeToString(&bytes);
            send_h3_proto(c, stream_id, bytes);
#endif
        } else {
            std::ostringstream oss;
            oss << "{"
                << "\"f_bsize\":" << v.f_bsize << ","
                << "\"f_frsize\":" << v.f_frsize << ","
                << "\"f_blocks\":" << v.f_blocks << ","
                << "\"f_bfree\":" << v.f_bfree << ","
                << "\"f_bavail\":" << v.f_bavail << ","
                << "\"f_files\":" << v.f_files << ","
                << "\"f_ffree\":" << v.f_ffree << ","
                << "\"f_favail\":" << v.f_favail << ","
                << "\"f_namemax\":" << v.f_namemax
                << "}";
            send_h3_json(c, stream_id, 200, oss.str());
        }
        return;
    }

    send_h3_json(c, stream_id, 404, json_encode("error","not found"));
}

int main(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name)->std::string{
            if (i + 1 >= argc) { std::cerr << "missing value for " << name << "\n"; std::exit(2); }
            return std::string(argv[++i]);
        };
        if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (a == "--host") args.host = need("--host");
        else if (a == "--port") args.port = std::stoi(need("--port"));
        else if (a == "--storage") args.storage = need("--storage");
        else if (a == "--cert") args.cert = need("--cert");
        else if (a == "--key") args.key = need("--key");
        else if (a == "--flat") args.flat = true;
        else if (a == "--durable-writes") args.durable = true;
        else if (a == "--read-ahead-bytes") args.read_ahead = std::stoi(need("--read-ahead-bytes"));
        else if (a == "--verbose" || a == "-v") args.verbose = true;
        else if (a == "--token") args.token = need("--token");
        else if (a == "--enable-control") args.enable_control = true;
        else if (a == "--control-host") args.control_host = need("--control-host");
        else if (a == "--control-port") args.control_port = std::stoi(need("--control-port"));
        else if (a == "--client-id") args.client_id = need("--client-id");
        else if (a == "--remote") args.remote = need("--remote");
        else if (a == "--public-host") args.public_host = need("--public-host");
        else if (a == "--public-port") args.public_port = std::stoi(need("--public-port"));
        else {
            std::cerr << "Unknown arg: " << a << "\n";
            print_usage(argv[0]);
            return 2;
        }
    }

    if (args.verbose) {
        quiche_enable_debug_logging([](const char* line, void*) {
            fprintf(stderr, "[quiche] %s\n", line);
        }, nullptr);
    }

    // Socket
    Server s; s.args = args;
    // Ensure storage root exists
    {
        std::error_code ec;
        std::filesystem::create_directories(s.args.storage, ec);
    }
    s.sock = make_udp_socket(args.host, args.port, s.local, s.local_len);
    if (s.sock < 0) { std::cerr << "bind failed\n"; return 1; }
    set_nonblocking(s.sock);

    // QUIC config
    s.qcfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    // const uint8_t alpn[] = { 0x02, 'h', '3' };
    const uint8_t alpn[] = {
        0x05, 'h','3','-','2','9',
        0x05, 'h','3','-','3','0',
        0x05, 'h','3','-','3','1',
        0x05, 'h','3','-','3','2',
        0x02, 'h', '3'
    };
    quiche_config_set_application_protos(s.qcfg, alpn, sizeof(alpn));
    // Allow multiple QUIC versions (if supported by quiche build)
    // Optional: widen QUIC versions if your quiche build supports it.
    // The C FFI in some releases does not export a versions setter; rely on defaults + ALPN.
    // #if 0
    // {
    //     uint32_t versions[] = {
    //         QUICHE_PROTOCOL_VERSION,  // negotiated default
    //         0x00000001,               // QUIC v1
    //         0x00000002                // QUIC v2 (if client supports)
    //     };
    //     quiche_config_set_protocol_versions(s.qcfg, versions, sizeof(versions) / sizeof(versions[0]));
    // }
    // #endif
    quiche_config_set_max_idle_timeout(s.qcfg, 45000);
    quiche_config_set_disable_active_migration(s.qcfg, true);
    add_fc_windows(s.qcfg);
    if (quiche_config_load_cert_chain_from_pem_file(s.qcfg, args.cert.c_str()) != 0 ||
        quiche_config_load_priv_key_from_pem_file(s.qcfg, args.key.c_str()) != 0) {
        std::cerr << "failed to load TLS cert/key\n"; return 1;
    }

    std::cout << "[gateway-cpp] listening on https://" << args.host << ":" << args.port << " (HTTP/3)\n";
    std::cout << "[gateway-cpp] storage root: " << std::filesystem::weakly_canonical(s.args.storage) << "\n";

    // Kick off control registration in background if enabled
    if (args.enable_control && !args.control_host.empty() && !args.client_id.empty()) {
        std::thread t(control_register_and_mount_async, args);
        t.detach();
    }

    std::vector<uint8_t> buf(65536);
    std::vector<uint8_t> out(1350);

    while (true) {
        struct pollfd pfd{ s.sock, POLLIN, 0 };
        int pr = poll(&pfd, 1, 50);
        (void)pr;

        sockaddr_storage from{}; socklen_t from_len = sizeof(from);
        ssize_t read = recvfrom(s.sock, buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
        if (read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // try sending queued
        } else if (read >= 0) {
            // find or create connection
            uint8_t scid[16]; for (size_t i = 0; i < sizeof(scid); ++i) scid[i] = (uint8_t)rand();
            quiche_recv_info rinfo{};
            rinfo.from = (sockaddr*)&from; rinfo.from_len = from_len;
            rinfo.to = (sockaddr*)&s.local; rinfo.to_len = s.local_len;

            // Parse the header to see if it's a new Initial
            int cb = 0;
            std::string pk = peer_key(from, from_len);
            auto it = s.conns.find(pk);
            Conn* conn_ptr = nullptr;
            if (it == s.conns.end()) {
                quiche_conn* q = quiche_accept(scid, sizeof(scid), nullptr, 0, (sockaddr*)&s.local, s.local_len, (sockaddr*)&from, from_len, s.qcfg);
                if (q != nullptr) {
                    Conn c{};
                    c.peer = from; c.peer_len = from_len;
                    c.local = s.local; c.local_len = s.local_len;
                    c.q = q;
                    c.h3cfg = quiche_h3_config_new();
                    // Reasonable H3 limits; QPACK disabled (table capacity 0)
                    quiche_h3_config_set_max_field_section_size(c.h3cfg, 16 * 1024);
                    quiche_h3_config_set_qpack_max_table_capacity(c.h3cfg, 0);
                    quiche_h3_config_set_qpack_blocked_streams(c.h3cfg, 0);
                    c.h3 = nullptr; // after handshake
                    c.last_tick = std::chrono::steady_clock::now();
                    s.conns.emplace(pk, std::move(c));
                    conn_ptr = &s.conns[pk];
                }
            } else {
                conn_ptr = &it->second;
            }

            if (conn_ptr) {
                quiche_conn* q = conn_ptr->q;
                ssize_t done = quiche_conn_recv(q, buf.data(), (size_t)read, &rinfo);
                if (done < 0 && done != QUICHE_ERR_DONE) {
                    // drop connection
                    s.conns.erase(pk);
                } else {
                    if (quiche_conn_is_established(q)) {
                        if (conn_ptr->h3 == nullptr) {
                            conn_ptr->h3 = quiche_h3_conn_new_with_transport(q, conn_ptr->h3cfg);
                            std::cout << "[gateway-cpp] handshake complete " << pk << " (H3 created)\n";
                        }
                        // Debug: list readable streams before polling H3
                        if (s.args.verbose) {
                            quiche_stream_iter* it = quiche_conn_readable(q);
                            uint64_t rsid = 0;
                            while (quiche_stream_iter_next(it, &rsid)) {
                                std::cout << "[gateway-cpp] readable stream=" << rsid << "\n";
                            }
                            quiche_stream_iter_free(it);
                        }
                        // Poll H3 events
                        while (true) {
                            quiche_h3_event* ev = nullptr;
                            int64_t sid = quiche_h3_conn_poll(conn_ptr->h3, q, &ev);
                            if (sid < 0) break;
                            int t = quiche_h3_event_type(ev);
                            if (t == QUICHE_H3_EVENT_HEADERS) {
                                std::vector<std::pair<std::string,std::string>> hv;
                                quiche_h3_event_for_each_header(ev, [](uint8_t* name, size_t name_len, uint8_t* value, size_t value_len, void* arg)->int{
                                    auto* v = reinterpret_cast<std::vector<std::pair<std::string,std::string>>*>(arg);
                                    v->push_back({ std::string((char*)name, name_len), std::string((char*)value, value_len) });
                                    return 0;
                                }, &hv);
                                Conn::ReqCtx ctx;
                                for (auto &h : hv) {
                                    if (h.first == ":method") ctx.method = h.second;
                                    else if (h.first == ":path") ctx.path = h.second;
                                    else if (h.first == "content-type") ctx.content_type = h.second;
                                    else if (h.first == "accept") ctx.accept = h.second;
                                    else if (h.first == "authorization") ctx.authorization = h.second;
                                    else if (h.first == "x-vix-client-id") ctx.client_id = h.second;
                                }
                                std::cout << "[gateway-cpp] headers sid=" << (uint64_t)sid << " " << (ctx.method.empty()?"?":ctx.method) << " " << (ctx.path.empty()?"/":ctx.path) << "\n";
                                if (s.args.verbose) {
                                    for (auto &h : hv) {
                                        std::cout << "  hdr " << h.first << ": " << h.second << "\n";
                                    }
                                }
                                // Store context
                                conn_ptr->reqs[(uint64_t)sid] = std::move(ctx);
                                // For header-only requests (e.g., GET), respond immediately without waiting for FIN
                                auto &rc = conn_ptr->reqs[(uint64_t)sid];
                                // Auth check (if token configured)
                                if (!s.args.token.empty()) {
                                    std::string expect = std::string("Bearer ") + s.args.token;
                                    if (rc.authorization != expect) {
                                        send_h3_json(*conn_ptr, (uint64_t)sid, 401, "{\"error\":\"unauthorized\"}");
                                        conn_ptr->reqs.erase((uint64_t)sid);
                                        continue;
                                    }
                                }
                                if (rc.method != "POST" && rc.method != "PUT") {
                                    h3_route(s, *conn_ptr, (uint64_t)sid, rc.method.empty()?"GET":rc.method, rc.path.empty()?"/":rc.path, rc.content_type, rc.body);
                                    conn_ptr->reqs.erase((uint64_t)sid);
                                }
                            } else if (t == QUICHE_H3_EVENT_DATA) {
                                auto itx = conn_ptr->reqs.find((uint64_t)sid);
                                if (itx == conn_ptr->reqs.end()) { quiche_h3_event_free(ev); continue; }
                                uint8_t tmp[16*1024];
                                while (true) {
                                    ssize_t n = quiche_h3_recv_body(conn_ptr->h3, q, (uint64_t)sid, tmp, sizeof(tmp));
                                    if (n == QUICHE_H3_ERR_DONE || n == QUICHE_H3_ERR_BUFFER_TOO_SHORT) break;
                                    if (n < 0) break;
                                    itx->second.body.append((const char*)tmp, (size_t)n);
                                    if (s.args.verbose) {
                                        std::cout << "[gateway-cpp] data sid=" << (uint64_t)sid << " +=" << n << " total=" << itx->second.body.size() << "\n";
                                    }
                                }
                            } else if (t == QUICHE_H3_EVENT_FINISHED) {
                                auto itx = conn_ptr->reqs.find((uint64_t)sid);
                                if (itx != conn_ptr->reqs.end()) {
                                    std::cout << "[gateway-cpp] finished sid=" << (uint64_t)sid << "\n";
                                    h3_route(s, *conn_ptr, (uint64_t)sid, itx->second.method.empty()?"GET":itx->second.method, itx->second.path.empty()?"/":itx->second.path, itx->second.content_type, itx->second.body);
                                    conn_ptr->reqs.erase(itx);
                                }
                            }
                            quiche_h3_event_free(ev);
                        }
                    }
                }
            }
        }

        // transmit for all connections
        for (auto itc = s.conns.begin(); itc != s.conns.end(); ) {
            quiche_conn* q = itc->second.q;
            quiche_send_info sinfo{};
            sinfo.to = itc->second.peer; sinfo.to_len = itc->second.peer_len;
            sinfo.from = itc->second.local; sinfo.from_len = itc->second.local_len;
            while (true) {
                ssize_t written = quiche_conn_send(q, out.data(), out.size(), &sinfo);
                if (written == QUICHE_ERR_DONE) break;
                if (written < 0) { break; }
                ssize_t sent = sendto(s.sock, out.data(), (size_t)written, 0, (sockaddr*)&itc->second.peer, itc->second.peer_len);
                if (sent < 0) break;
            }
            if (quiche_conn_is_closed(q)) {
                itc = s.conns.erase(itc);
            } else {
                ++itc;
            }
        }
    }
    return 0;
}


