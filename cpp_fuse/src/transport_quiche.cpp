#include "transport.h"

#ifdef QUICHE_AVAILABLE
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <mutex>
#include <chrono>

static bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int resolve_udp(const std::string& host, int port, sockaddr_storage &addr, socklen_t &addr_len) {
    std::string service = std::to_string(port);
    struct addrinfo hints; std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (rc != 0) return -1;
    int fd = -1;
    for (auto p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        std::memcpy(&addr, p->ai_addr, p->ai_addrlen);
        addr_len = (socklen_t)p->ai_addrlen;
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static bool drive_io(int sockfd, quiche_conn *conn,
                     const struct sockaddr *local_addr, socklen_t local_len,
                     const struct sockaddr *peer_addr, socklen_t peer_len) {
    uint8_t out[1350];
    while (true) {
        quiche_send_info send_info;
        std::memset(&send_info, 0, sizeof(send_info));
        std::memcpy(&send_info.to, peer_addr, peer_len);
        send_info.to_len = peer_len;
        std::memcpy(&send_info.from, local_addr, local_len);
        send_info.from_len = local_len;
        ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);
        if (written == QUICHE_ERR_DONE) break;
        if (written < 0) return false;
        ssize_t sent = send(sockfd, out, (size_t)written, 0);
        if (sent < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) break;
            return false;
        }
    }
    return true;
}

struct PooledConn {
    int sockfd{-1};
    sockaddr_storage peer_addr{}; socklen_t peer_len{0};
    sockaddr_storage local_addr{}; socklen_t local_len{0};
    quiche_config *qcfg{nullptr};
    quiche_conn *conn{nullptr};
    quiche_h3_config *h3cfg{nullptr};
    quiche_h3_conn *h3{nullptr};
    int idle_ms{0};
    std::chrono::steady_clock::time_point last_used{};
};

static std::mutex g_pool_mutex;
static PooledConn g_pool;

static void pool_close(PooledConn &p) {
    if (p.h3) { quiche_h3_conn_free(p.h3); p.h3 = nullptr; }
    if (p.h3cfg) { quiche_h3_config_free(p.h3cfg); p.h3cfg = nullptr; }
    if (p.conn) { quiche_conn_free(p.conn); p.conn = nullptr; }
    if (p.qcfg) { quiche_config_free(p.qcfg); p.qcfg = nullptr; }
    if (p.sockfd >= 0) { close(p.sockfd); p.sockfd = -1; }
}

static bool pool_connect(PooledConn &p, const Http3ClientConfig& cfg) {
    pool_close(p);
    p.sockfd = resolve_udp(cfg.host, cfg.port, p.peer_addr, p.peer_len);
    if (p.sockfd < 0) return false;
    set_nonblocking(p.sockfd);
    if (connect(p.sockfd, (const struct sockaddr*)&p.peer_addr, p.peer_len) < 0) {
        pool_close(p); return false;
    }
    p.local_len = sizeof(p.local_addr);
    std::memset(&p.local_addr, 0, sizeof(p.local_addr));
    if (getsockname(p.sockfd, (struct sockaddr*)&p.local_addr, &p.local_len) < 0) {
        pool_close(p); return false;
    }
    p.qcfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (!p.qcfg) { pool_close(p); return false; }
    // Advertise the same HTTP/3 ALPN list as the gateway for maximum interop
    const uint8_t alpn[] = {
        0x05, 'h','3','-','2','9',
        0x05, 'h','3','-','3','0',
        0x05, 'h','3','-','3','1',
        0x05, 'h','3','-','3','2',
        0x02, 'h','3'
    };
    if (quiche_config_set_application_protos(p.qcfg, alpn, sizeof(alpn)) != 0) {
        pool_close(p); return false;
    }
    p.idle_ms = (30 + (std::rand() % 31)) * 1000; // 30..60 seconds
    quiche_config_set_max_idle_timeout(p.qcfg, p.idle_ms);
    // Increase flow control windows for large transfers
    quiche_config_set_initial_max_data(p.qcfg, 128 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_bidi_local(p.qcfg, 32 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_bidi_remote(p.qcfg, 32 * 1024 * 1024);
    quiche_config_set_initial_max_stream_data_uni(p.qcfg, 1 * 1024 * 1024);
    quiche_config_set_initial_max_streams_bidi(p.qcfg, 1024);
    quiche_config_set_initial_max_streams_uni(p.qcfg, 256);
    quiche_config_set_disable_dcid_reuse(p.qcfg, true);
    quiche_config_verify_peer(p.qcfg, false);
    uint8_t scid[16]; for (size_t i = 0; i < sizeof(scid); ++i) scid[i] = (uint8_t)rand();
    p.conn = quiche_connect(
        cfg.host.c_str(),
        scid, sizeof(scid),
        (const struct sockaddr*)&p.local_addr, p.local_len,
        (const struct sockaddr*)&p.peer_addr, p.peer_len,
        p.qcfg);
    if (!p.conn) { pool_close(p); return false; }
    if (!drive_io(p.sockfd, p.conn, (const struct sockaddr*)&p.local_addr, p.local_len,
                  (const struct sockaddr*)&p.peer_addr, p.peer_len)) { pool_close(p); return false; }
    uint8_t recv_buf[2048];
    while (!quiche_conn_is_established(p.conn)) {
        sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
        ssize_t read = recvfrom(p.sockfd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&from_addr, &from_len);
        if (read < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                if (!drive_io(p.sockfd, p.conn, (const struct sockaddr*)&p.local_addr, p.local_len,
                              (const struct sockaddr*)&p.peer_addr, p.peer_len)) return false;
                continue;
            }
            pool_close(p); return false;
        }
        quiche_recv_info rinfo; std::memset(&rinfo, 0, sizeof(rinfo));
        rinfo.from = (struct sockaddr*)&from_addr; rinfo.from_len = from_len;
        rinfo.to = (struct sockaddr*)&p.local_addr; rinfo.to_len = p.local_len;
        ssize_t done = quiche_conn_recv(p.conn, recv_buf, (size_t)read, &rinfo);
        if (done < 0 && done != QUICHE_ERR_DONE) { pool_close(p); return false; }
        if (!drive_io(p.sockfd, p.conn, (const struct sockaddr*)&p.local_addr, p.local_len,
                      (const struct sockaddr*)&p.peer_addr, p.peer_len)) return false;
    }
    p.h3cfg = quiche_h3_config_new();
    if (!p.h3cfg) { pool_close(p); return false; }
    p.h3 = quiche_h3_conn_new_with_transport(p.conn, p.h3cfg);
    if (!p.h3) { pool_close(p); return false; }
    p.last_used = std::chrono::steady_clock::now();
    return true;
}

static bool pool_ensure(PooledConn &p, const Http3ClientConfig& cfg) {
    if (p.conn && !quiche_conn_is_closed(p.conn)) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - p.last_used).count();
        if (elapsed_ms < p.idle_ms) return true;
        pool_close(p);
    }
    return pool_connect(p, cfg);
}

static bool quiche_h3_request(const Http3ClientConfig& cfg,
                              const std::string& method,
                              const std::string& path,
                              const std::string& body,
                              std::string& json_out) {
    std::lock_guard<std::mutex> lock(g_pool_mutex);
    if (!pool_ensure(g_pool, cfg)) return false;

    std::string host_header = cfg.host + ":" + std::to_string(cfg.port);
    std::string method_val = method;
    std::string scheme_val = std::string("https");
    std::string path_val = path;
    std::string authority_val = host_header;
    std::string accept_val = std::string("application/json");
    std::string content_type_val = std::string("application/json");

    std::vector<quiche_h3_header> hdrs;
    auto push_hdr_sv = [&](const char* name, const std::string& value) {
        quiche_h3_header h;
        h.name = (uint8_t*)name;
        h.name_len = std::strlen(name);
        h.value = (uint8_t*)value.c_str();
        h.value_len = value.size();
        hdrs.push_back(h);
    };
    push_hdr_sv(":method", method_val);
    push_hdr_sv(":scheme", scheme_val);
    push_hdr_sv(":authority", authority_val);
    push_hdr_sv(":path", path_val);
    push_hdr_sv("accept", accept_val);
    if (!cfg.token.empty()) {
        std::string bearer = std::string("Bearer ") + cfg.token;
        push_hdr_sv("authorization", bearer);
    }
    if (!cfg.client_id.empty()) {
        push_hdr_sv("x-client-id", cfg.client_id);
    }
    if (method == "POST") push_hdr_sv("content-type", content_type_val);

    bool fin_headers = body.empty();
    int64_t stream_id = quiche_h3_send_request(g_pool.h3, g_pool.conn, hdrs.data(), hdrs.size(), fin_headers);
    if (stream_id < 0) { pool_close(g_pool); return false; }

    // Stream body in chunks with backpressure handling
    if (!fin_headers) {
        size_t sent = 0;
        const uint8_t* ptr = (const uint8_t*)body.data();
        size_t total = body.size();
        while (sent < total) {
            size_t chunk = std::min((size_t)65536, total - sent);
            ssize_t r = quiche_h3_send_body(g_pool.h3, g_pool.conn, (uint64_t)stream_id, ptr + sent, chunk, (sent + chunk) == total);
            if (r == QUICHE_H3_ERR_BUFFER_TOO_SHORT || r == QUICHE_ERR_DONE) {
                // Drive IO and retry
                (void)drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                               (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len);
                // Also try to receive to process WINDOW_UPDATEs
                sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
                uint8_t recv_buf_tmp[1024];
                ssize_t rd = recvfrom(g_pool.sockfd, recv_buf_tmp, sizeof(recv_buf_tmp), 0, (struct sockaddr*)&from_addr, &from_len);
                if (rd > 0) {
                    quiche_recv_info rinfo; std::memset(&rinfo, 0, sizeof(rinfo));
                    rinfo.from = (struct sockaddr*)&from_addr; rinfo.from_len = from_len;
                    rinfo.to = (struct sockaddr*)&g_pool.local_addr; rinfo.to_len = g_pool.local_len;
                    (void)quiche_conn_recv(g_pool.conn, recv_buf_tmp, (size_t)rd, &rinfo);
                }
                continue;
            }
            if (r < 0) { pool_close(g_pool); return false; }
            sent += (size_t)r;
        }
    }

    if (!drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                  (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len)) { pool_close(g_pool); return false; }

    bool got_fin = false;
    uint8_t recv_buf[2048];
    while (!got_fin && !quiche_conn_is_closed(g_pool.conn)) {
        sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
        ssize_t read = recvfrom(g_pool.sockfd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&from_addr, &from_len);
        if (read < 0) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) break;
        } else {
            quiche_recv_info rinfo;
            std::memset(&rinfo, 0, sizeof(rinfo));
            rinfo.from = (struct sockaddr*)&from_addr;
            rinfo.from_len = from_len;
            rinfo.to = (struct sockaddr*)&g_pool.local_addr;
            rinfo.to_len = g_pool.local_len;
            ssize_t done = quiche_conn_recv(g_pool.conn, recv_buf, (size_t)read, &rinfo);
            if (done < 0 && done != QUICHE_ERR_DONE) break;
        }

        while (true) {
            quiche_h3_event *ev = nullptr;
            int64_t sid = quiche_h3_conn_poll(g_pool.h3, g_pool.conn, &ev);
            if (sid < 0) break;
            int ev_type = quiche_h3_event_type(ev);
            if (ev_type == QUICHE_H3_EVENT_DATA) {
                uint8_t b[4096];
                while (true) {
                    ssize_t n = quiche_h3_recv_body(g_pool.h3, g_pool.conn, (uint64_t)sid, b, sizeof(b));
                    if (n == QUICHE_H3_ERR_DONE || n == QUICHE_H3_ERR_BUFFER_TOO_SHORT) break;
                    if (n < 0) break;
                    json_out.append((const char*)b, (size_t)n);
                }
            } else if (ev_type == QUICHE_H3_EVENT_FINISHED) {
                got_fin = true;
            }
            quiche_h3_event_free(ev);
        }

        if (!drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                      (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len)) break;
    }
    g_pool.last_used = std::chrono::steady_clock::now();
    return got_fin;
}

bool h3_post_json(const Http3ClientConfig& cfg,
    const std::string& path,
    const std::string& json_in,
    std::string& json_out) {
    return quiche_h3_request(cfg, "POST", path, json_in, json_out);
}

bool h3_get_json(const Http3ClientConfig& cfg,
   const std::string& path,
   std::string& json_out) {
    std::string empty;
    return quiche_h3_request(cfg, "GET", path, empty, json_out);
}

static bool quiche_h3_request_octet(const Http3ClientConfig& cfg,
                              const std::string& method,
                              const std::string& path,
                              const std::string& body,
                              std::string& out_bytes) {
    std::lock_guard<std::mutex> lock(g_pool_mutex);
    if (!pool_ensure(g_pool, cfg)) return false;

    std::string host_header = cfg.host + ":" + std::to_string(cfg.port);
    std::string method_val = method;
    std::string scheme_val = std::string("https");
    std::string path_val = path;
    std::string authority_val = host_header;
    std::string accept_val = std::string("application/octet-stream");
    std::string content_type_val = std::string("application/octet-stream");

    std::vector<quiche_h3_header> hdrs;
    auto push_hdr_sv = [&](const char* name, const std::string& value) {
        quiche_h3_header h;
        h.name = (uint8_t*)name;
        h.name_len = std::strlen(name);
        h.value = (uint8_t*)value.c_str();
        h.value_len = value.size();
        hdrs.push_back(h);
    };
    push_hdr_sv(":method", method_val);
    push_hdr_sv(":scheme", scheme_val);
    push_hdr_sv(":authority", authority_val);
    push_hdr_sv(":path", path_val);
    push_hdr_sv("accept", accept_val);
    if (!cfg.token.empty()) {
        std::string bearer = std::string("Bearer ") + cfg.token;
        push_hdr_sv("authorization", bearer);
    }
    if (!cfg.client_id.empty()) {
        push_hdr_sv("x-client-id", cfg.client_id);
    }
    if (method == "POST") push_hdr_sv("content-type", content_type_val);

    bool fin_headers = body.empty();
    int64_t stream_id = quiche_h3_send_request(g_pool.h3, g_pool.conn, hdrs.data(), hdrs.size(), fin_headers);
    if (stream_id < 0) { pool_close(g_pool); return false; }

    if (!fin_headers) {
        size_t sent = 0;
        const uint8_t* ptr = (const uint8_t*)body.data();
        size_t total = body.size();
        while (sent < total) {
            size_t chunk = std::min((size_t)65536, total - sent);
            ssize_t r = quiche_h3_send_body(g_pool.h3, g_pool.conn, (uint64_t)stream_id, ptr + sent, chunk, (sent + chunk) == total);
            if (r == QUICHE_H3_ERR_BUFFER_TOO_SHORT || r == QUICHE_ERR_DONE) {
                // Drive IO and retry
                (void)drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                               (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len);
                // Also try to receive to process WINDOW_UPDATEs
                sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
                uint8_t recv_buf_tmp[1024];
                ssize_t rd = recvfrom(g_pool.sockfd, recv_buf_tmp, sizeof(recv_buf_tmp), 0, (struct sockaddr*)&from_addr, &from_len);
                if (rd > 0) {
                    quiche_recv_info rinfo; std::memset(&rinfo, 0, sizeof(rinfo));
                    rinfo.from = (struct sockaddr*)&from_addr; rinfo.from_len = from_len;
                    rinfo.to = (struct sockaddr*)&g_pool.local_addr; rinfo.to_len = g_pool.local_len;
                    (void)quiche_conn_recv(g_pool.conn, recv_buf_tmp, (size_t)rd, &rinfo);
                }
                continue;
            }
            if (r < 0) { pool_close(g_pool); return false; }
            sent += (size_t)r;
        }
    }

    if (!drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                  (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len)) { pool_close(g_pool); return false; }

    bool got_fin = false;
    uint8_t recv_buf[4096];
    while (!got_fin && !quiche_conn_is_closed(g_pool.conn)) {
        sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
        ssize_t read = recvfrom(g_pool.sockfd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&from_addr, &from_len);
        if (read < 0) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) break;
        } else {
            quiche_recv_info rinfo; std::memset(&rinfo, 0, sizeof(rinfo));
            rinfo.from = (struct sockaddr*)&from_addr; rinfo.from_len = from_len;
            rinfo.to = (struct sockaddr*)&g_pool.local_addr; rinfo.to_len = g_pool.local_len;
            ssize_t done = quiche_conn_recv(g_pool.conn, recv_buf, (size_t)read, &rinfo);
            if (done < 0 && done != QUICHE_ERR_DONE) break;
        }
        while (true) {
            quiche_h3_event *ev = nullptr;
            int64_t sid = quiche_h3_conn_poll(g_pool.h3, g_pool.conn, &ev);
            if (sid < 0) break;
            int ev_type = quiche_h3_event_type(ev);
            if (ev_type == QUICHE_H3_EVENT_DATA) {
                uint8_t b[4096];
                while (true) {
                    ssize_t n = quiche_h3_recv_body(g_pool.h3, g_pool.conn, (uint64_t)sid, b, sizeof(b));
                    if (n == QUICHE_H3_ERR_DONE || n == QUICHE_H3_ERR_BUFFER_TOO_SHORT) break;
                    if (n < 0) break;
                    out_bytes.append((const char*)b, (size_t)n);
                }
            } else if (ev_type == QUICHE_H3_EVENT_FINISHED) {
                got_fin = true;
            }
            quiche_h3_event_free(ev);
        }
        if (!drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                      (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len)) break;
    }
    g_pool.last_used = std::chrono::steady_clock::now();
    return got_fin;
}

bool h3_get_bytes(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes) {
    std::string empty;
    return quiche_h3_request_octet(cfg, "GET", path, empty, out_bytes);
}

bool h3_post_bytes(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    return quiche_h3_request_octet(cfg, "POST", path, in_bytes, out_bytes);
}

static bool quiche_h3_request_proto(const Http3ClientConfig& cfg,
                              const std::string& method,
                              const std::string& path,
                              const std::string& body,
                              std::string& out_bytes) {
    std::lock_guard<std::mutex> lock(g_pool_mutex);
    if (!pool_ensure(g_pool, cfg)) return false;

    std::string host_header = cfg.host + ":" + std::to_string(cfg.port);
    std::string method_val = method;
    std::string scheme_val = std::string("https");
    std::string path_val = path;
    std::string authority_val = host_header;
    std::string accept_val = std::string("application/x-protobuf");
    std::string content_type_val = std::string("application/x-protobuf");

    std::vector<quiche_h3_header> hdrs;
    auto push_hdr_sv = [&](const char* name, const std::string& value) {
        quiche_h3_header h; h.name=(uint8_t*)name; h.name_len=std::strlen(name); h.value=(uint8_t*)value.c_str(); h.value_len=value.size(); hdrs.push_back(h);
    };
    push_hdr_sv(":method", method_val);
    push_hdr_sv(":scheme", scheme_val);
    push_hdr_sv(":authority", authority_val);
    push_hdr_sv(":path", path_val);
    push_hdr_sv("accept", accept_val);
    if (!cfg.token.empty()) { std::string bearer = std::string("Bearer ") + cfg.token; push_hdr_sv("authorization", bearer); }
    if (!cfg.client_id.empty()) { push_hdr_sv("x-client-id", cfg.client_id); }
    if (method == "POST") push_hdr_sv("content-type", content_type_val);

    bool fin_headers = body.empty();
    int64_t stream_id = quiche_h3_send_request(g_pool.h3, g_pool.conn, hdrs.data(), hdrs.size(), fin_headers);
    if (stream_id < 0) { pool_close(g_pool); return false; }
    if (!fin_headers) {
        size_t sent = 0;
        const uint8_t* ptr = (const uint8_t*)body.data();
        size_t total = body.size();
        while (sent < total) {
            size_t chunk = std::min((size_t)65536, total - sent);
            ssize_t r = quiche_h3_send_body(g_pool.h3, g_pool.conn, (uint64_t)stream_id, ptr + sent, chunk, (sent + chunk) == total);
            if (r == QUICHE_H3_ERR_BUFFER_TOO_SHORT || r == QUICHE_ERR_DONE) {
                (void)drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                               (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len);
                sockaddr_storage from_addr; socklen_t from_len = sizeof(from_addr);
                uint8_t recv_buf_tmp[1024];
                ssize_t rd = recvfrom(g_pool.sockfd, recv_buf_tmp, sizeof(recv_buf_tmp), 0, (struct sockaddr*)&from_addr, &from_len);
                if (rd > 0) {
                    quiche_recv_info rinfo; std::memset(&rinfo, 0, sizeof(rinfo));
                    rinfo.from = (struct sockaddr*)&from_addr; rinfo.from_len = from_len;
                    rinfo.to = (struct sockaddr*)&g_pool.local_addr; rinfo.to_len = g_pool.local_len;
                    (void)quiche_conn_recv(g_pool.conn, recv_buf_tmp, (size_t)rd, &rinfo);
                }
                continue;
            }
            if (r < 0) { pool_close(g_pool); return false; }
            sent += (size_t)r;
        }
    }
    if (!drive_io(g_pool.sockfd, g_pool.conn, (const struct sockaddr*)&g_pool.local_addr, g_pool.local_len,
                  (const struct sockaddr*)&g_pool.peer_addr, g_pool.peer_len)) { pool_close(g_pool); return false; }
    bool got_fin=false; uint8_t recv_buf[4096];
    while (!got_fin && !quiche_conn_is_closed(g_pool.conn)) {
        sockaddr_storage from_addr; socklen_t from_len=sizeof(from_addr);
        ssize_t read=recvfrom(g_pool.sockfd, recv_buf, sizeof(recv_buf), 0,(struct sockaddr*)&from_addr,&from_len);
        if (read>=0){ quiche_recv_info rinfo; std::memset(&rinfo,0,sizeof(rinfo)); rinfo.from=(struct sockaddr*)&from_addr; rinfo.from_len=from_len; rinfo.to=(struct sockaddr*)&g_pool.local_addr; rinfo.to_len=g_pool.local_len; ssize_t done=quiche_conn_recv(g_pool.conn, recv_buf,(size_t)read,&rinfo); if (done<0 && done!=QUICHE_ERR_DONE) break; }
        quiche_h3_event *ev=nullptr; int64_t sid=quiche_h3_conn_poll(g_pool.h3, g_pool.conn, &ev); while (sid>=0){ int t=quiche_h3_event_type(ev); if (t==QUICHE_H3_EVENT_DATA){ uint8_t b[4096]; while(true){ ssize_t n=quiche_h3_recv_body(g_pool.h3,g_pool.conn,(uint64_t)sid,b,sizeof(b)); if (n==QUICHE_H3_ERR_DONE||n==QUICHE_H3_ERR_BUFFER_TOO_SHORT) break; if (n<0) break; out_bytes.append((const char*)b,(size_t)n);} } else if (t==QUICHE_H3_EVENT_FINISHED){ got_fin=true;} quiche_h3_event_free(ev); sid=quiche_h3_conn_poll(g_pool.h3, g_pool.conn, &ev);}        
        if (!drive_io(g_pool.sockfd, g_pool.conn,(const struct sockaddr*)&g_pool.local_addr,g_pool.local_len,(const struct sockaddr*)&g_pool.peer_addr,g_pool.peer_len)) break;
    }
    g_pool.last_used=std::chrono::steady_clock::now();
    return got_fin;
}

bool h3_get_proto(const Http3ClientConfig& cfg, const std::string& path, std::string& out_bytes) {
    std::string empty; return quiche_h3_request_proto(cfg, "GET", path, empty, out_bytes);
}

bool h3_post_proto(const Http3ClientConfig& cfg, const std::string& path, const std::string& in_bytes, std::string& out_bytes) {
    return quiche_h3_request_proto(cfg, "POST", path, in_bytes, out_bytes);
}

#else

bool h3_post_json(const Http3ClientConfig& /*cfg*/, const std::string& /*path*/, const std::string& /*json_in*/, std::string& /*json_out*/) {
    return false;
}

bool h3_get_json(const Http3ClientConfig& /*cfg*/, const std::string& /*path*/, std::string& /*json_out*/) {
    return false;
}

#endif


