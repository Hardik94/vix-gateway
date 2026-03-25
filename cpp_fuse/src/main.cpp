#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <sys/stat.h>
#include <cstring>
#include <string>
#include <iostream>
#include <memory>
#include "transport.h"
#include <algorithm>
#include <vector>
#include <errno.h>
#include <unordered_map>
#include <mutex>
#include <thread>
#ifdef USE_PROTOBUF
#include "fs.pb.h"
#endif

struct Config {
    std::string gateway_host;
    int gateway_port{9443};
    std::string gateway_token;
    bool perf_cache{false};
    // Optional: resolve via control server
    bool use_control{false};
    std::string control_host;
    int control_port{9444};
    std::string client_id;
    // Optional: proxy all /fs/* via control server LB
    bool control_proxy{false};
};

static Config g_cfg;

static inline bool h3_post(const std::string &path, const std::string &json_in, std::string &json_out) {
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token, (g_cfg.control_proxy ? g_cfg.client_id : std::string())};
    return h3_post_json(cfg, path, json_in, json_out);
}

static inline bool h3_get(const std::string &path, std::string &json_out) {
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token, (g_cfg.control_proxy ? g_cfg.client_id : std::string())};
    return h3_get_json(cfg, path, json_out);
}

static inline bool h3_get_proto_wrap(const std::string &path, std::string &bytes_out) {
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token, (g_cfg.control_proxy ? g_cfg.client_id : std::string())};
    return h3_get_proto(cfg, path, bytes_out);
}

static bool parse_quic_url(const std::string &url, std::string &host, int &port) {
    // Expect formats: quic://host:port or https://host:port
    std::string u = url;
    auto pos = u.find("://");
    if (pos != std::string::npos) u = u.substr(pos + 3);
    auto c = u.rfind(':');
    if (c == std::string::npos) return false;
    host = u.substr(0, c);
    try { port = std::stoi(u.substr(c + 1)); } catch (...) { return false; }
    return !host.empty() && port > 0;
}

static bool resolve_gateway_from_control() {
    if (!g_cfg.use_control || g_cfg.control_host.empty() || g_cfg.client_id.empty()) return false;
    std::string out;
    Http3ClientConfig ccfg{g_cfg.control_host, g_cfg.control_port, ""};
    if (!h3_get_json(ccfg, std::string("/resolve?client_id=") + g_cfg.client_id, out)) {
        std::cerr << "control: resolve request failed\n";
        return false;
    }
    // Trivial parse for "gateway_url":"...":
    auto key = std::string("\"gateway_url\"");
    auto p = out.find(key);
    if (p == std::string::npos) {
        std::cerr << "control: no gateway_url in response\n";
        return false;
    }
    p = out.find(':', p);
    if (p == std::string::npos) return false;
    // find opening quote
    size_t q1 = out.find('"', p);
    if (q1 == std::string::npos) return false;
    size_t q2 = out.find('"', q1 + 1);
    if (q2 == std::string::npos || q2 <= q1 + 1) return false;
    std::string url = out.substr(q1 + 1, q2 - (q1 + 1));
    std::string host; int port = 0;
    if (!parse_quic_url(url, host, port)) {
        std::cerr << "control: bad gateway_url format: " << url << "\n";
        return false;
    }
    g_cfg.gateway_host = host;
    g_cfg.gateway_port = port;
    std::cout << "control: resolved gateway to " << host << ":" << port << "\n";
    return true;
}

static inline int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::vector<unsigned char> base64_decode(const std::string &in) {
    std::vector<unsigned char> out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) continue;
        val = (val << 6) + v;
        valb += 6;
        if (valb >= 0) {
            out.push_back((unsigned char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static std::string base64_encode(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < len) {
        unsigned int n = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back(tbl[n & 63]);
        i += 3;
    }
    if (i + 1 == len) {
        unsigned int n = (data[i] << 16);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == len) {
        unsigned int n = (data[i] << 16) | (data[i+1] << 8);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

static void* vix_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;
    if (g_cfg.perf_cache) {
        cfg->kernel_cache = 1;
        cfg->attr_timeout = 1.0;
        cfg->entry_timeout = 1.0;
    } else {
        cfg->kernel_cache = 0;
        cfg->attr_timeout = 0.0;
        cfg->entry_timeout = 0.0;
    }
    std::cout << "vix_cpp_fuse: init complete" << std::endl;
    return nullptr;
}

// Read-ahead cache and write buffering for small ops
static const size_t READ_AHEAD_SIZE = 128 * 1024;
struct ReadCacheEntry { off_t base{0}; std::string data; };
struct WriteBuffer { off_t base{-1}; std::string data; };
static std::unordered_map<std::string, ReadCacheEntry> g_read_cache;
static std::unordered_map<std::string, WriteBuffer> g_write_buf;
static std::mutex g_rw_mutex;

static void flush_write_locked(const std::string &path, Http3ClientConfig &cfg) {
    auto it = g_write_buf.find(path);
    if (it == g_write_buf.end()) return;
    if (it->second.data.empty() || it->second.base < 0) { g_write_buf.erase(it); return; }
    std::string out;
    std::string qpath = std::string("/fs/write?path=") + path + "&offset=" + std::to_string((long long)it->second.base);
    std::string body = it->second.data;
    (void)h3_post_bytes(cfg, qpath, body, out);
    g_write_buf.erase(path);
}

static int vix_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    std::cout << "[fuse] getattr path=" << (path?path:"") << std::endl;
    memset(stbuf, 0, sizeof(struct stat));
    std::string out;
    std::string spath = (std::string(path).empty()?"/":path);
#ifdef USE_PROTOBUF
    {
        std::string bytes;
        std::string qpath = std::string("/fs/stat?path=") + spath;
        if (h3_get_proto_wrap(qpath, bytes)) {
            vix::fs::FsStatResponse resp;
            if (resp.ParseFromArray(bytes.data(), (int)bytes.size())) {
                bool mdir = resp.is_dir();
                stbuf->st_mode = (mdir ? S_IFDIR : S_IFREG) | 0755;
                stbuf->st_nlink = mdir ? 2 : 1;
                stbuf->st_size = (off_t)resp.size();
                return 0;
            }
        }
    }
#endif
    std::string in = std::string("{") + "\"path\":\"" + spath + "\"}";
    if (!h3_post("/fs/stat", in, out)) {
        // Fallback: only treat root as directory; others ENOENT
        if (std::string(path) == "/") {
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            stbuf->st_size = 0;
            return 0;
        }
        return -ENOENT;
    }
    // Very small JSON parse (avoid dependency): look for keys
    if (out.find("\"error\"") != std::string::npos) return -ENOENT;
    auto mode_pos = out.find("\"mode\":");
    auto size_pos = out.find("\"size\":");
    bool mdir = (out.find("\"is_dir\":true") != std::string::npos);
    long mode_val = 0;
    if (mode_pos != std::string::npos) {
        try { mode_val = std::stol(out.substr(mode_pos+7)); } catch (...) { mode_val = 0; }
        if ((mode_val & S_IFDIR) == S_IFDIR) mdir = true;
    }
    // Ensure root is always a directory, even if server omits fields
    if (std::string(path) == "/") mdir = true;
    stbuf->st_mode = (mdir ? S_IFDIR : S_IFREG) | 0755;
    stbuf->st_nlink = mdir ? 2 : 1;
    if (size_pos != std::string::npos) {
        try { stbuf->st_size = std::stoll(out.substr(size_pos+8)); } catch (...) {}
    }
    return 0;
}

static int vix_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info *, enum fuse_readdir_flags) {
    std::cout << "[fuse] readdir path=" << (path?path:"") << std::endl;
    std::string out;
#ifdef USE_PROTOBUF
    {
        std::string bytes;
        std::string qpath = std::string("/fs/readdir?path=") + (std::string(path).empty()?"/":path);
        if (h3_get_proto_wrap(qpath, bytes)) {
            vix::fs::FsReaddirResponse resp;
            if (resp.ParseFromArray(bytes.data(), (int)bytes.size())) {
                filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
                filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
                for (const auto &e : resp.entries()) {
                    filler(buf, e.name().c_str(), nullptr, 0, (fuse_fill_dir_flags)0);
                }
                return 0;
            }
        }
    }
#endif
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\"}";
    if (!h3_post("/fs/readdir", in, out)) {
        filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
        filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
        return 0;
    }
    if (out.find("\"error\"") != std::string::npos) {
        filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
        filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
        return 0;
    }
    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
    // tolerant parse: find occurrences of "name" : "..."
    size_t pos = 0;
    const std::string key = "\"name\"";
    while ((pos = out.find(key, pos)) != std::string::npos) {
        size_t colon = out.find(':', pos + key.size());
        if (colon == std::string::npos) break;
        // skip whitespace
        size_t q = colon + 1;
        while (q < out.size() && (out[q] == ' ' || out[q] == '\t' || out[q] == '\n' || out[q] == '\r')) q++;
        if (q >= out.size() || out[q] != '"') { pos = q; continue; }
        q++;
        size_t end = q;
        while (end < out.size() && out[end] != '"') end++;
        if (end > q) {
            std::string name = out.substr(q, end - q);
            filler(buf, name.c_str(), nullptr, 0, (fuse_fill_dir_flags)0);
        }
        pos = (end < out.size() ? end + 1 : end);
    }
    return 0;
}

static int vix_open(const char *path, struct fuse_file_info *fi) {
    std::cout << "[fuse] open path=" << (path?path:"") << " flags=" << fi->flags << std::endl;
    (void)fi;
    // Allow open; validate presence via stat but don't block
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\"}";
    h3_post("/fs/stat", in, out); // ignore result
    return 0;
}

static int vix_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    std::cout << "[fuse] read path=" << (path?path:"") << " size=" << size << " off=" << (long long)offset << std::endl;
    (void)fi;
    std::string p = (std::string(path).empty()?"/":path);
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token};
    {
        std::lock_guard<std::mutex> lock(g_rw_mutex);
        auto it = g_read_cache.find(p);
        if (it != g_read_cache.end()) {
            off_t rel = offset - it->second.base;
            if (rel >= 0 && (size_t)rel < it->second.data.size()) {
                size_t n = std::min((size_t)size, it->second.data.size() - (size_t)rel);
                if (n > 0) std::memcpy(buf, it->second.data.data() + rel, n);
                return (int)n;
            }
        }
    }
    size_t fetch_sz = std::max(size, READ_AHEAD_SIZE);
    std::string bytes_out;
    std::string qpath = std::string("/fs/read?path=") + p +
                        "&offset=" + std::to_string((long long)offset) +
                        "&size=" + std::to_string((long long)fetch_sz);
    if (!h3_get_bytes(cfg, qpath, bytes_out)) return 0;
    {
        std::lock_guard<std::mutex> lock(g_rw_mutex);
        g_read_cache[p] = ReadCacheEntry{offset, bytes_out};
    }
    size_t n = std::min(bytes_out.size(), size);
    if (n > 0) std::memcpy(buf, bytes_out.data(), n);
    return (int)n;
}

static int vix_create(const char *path, mode_t, struct fuse_file_info *fi) {
    std::cout << "[fuse] create path=" << (path?path:"") << std::endl;
    (void)fi;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\",\"size\":0}";
    if (!h3_post("/fs/truncate", in, out)) {
        return -EIO;
    }
    if (out.find("\"error\"") != std::string::npos) {
        return -EIO;
    }
    return 0;
}

static int vix_mknod(const char *path, mode_t mode, dev_t) {
    // Only support regular files via truncate to 0
    if (!S_ISREG(mode)) return -EOPNOTSUPP;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\",\"size\":0}";
    if (!h3_post("/fs/truncate", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_truncate(const char *path, off_t size, struct fuse_file_info *) {
    std::cout << "[fuse] truncate path=" << (path?path:"") << " size=" << (long long)size << std::endl;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\",\"size\":" + std::to_string((long long)size) + "}";
    if (!h3_post("/fs/truncate", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    std::cout << "[fuse] write path=" << (path?path:"") << " size=" << size << " off=" << (long long)offset << std::endl;
    (void)fi;
    std::string p = (std::string(path).empty()?"/":path);
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token};
    std::lock_guard<std::mutex> lock(g_rw_mutex);
    auto &wb = g_write_buf[p];
    if (wb.data.empty()) {
        wb.base = offset;
        wb.data.assign(buf, buf + size);
    } else {
        off_t expected = wb.base + (off_t)wb.data.size();
        if (offset == expected) {
            wb.data.append(buf, buf + size);
        } else {
            flush_write_locked(p, cfg);
            wb.base = offset;
            wb.data.assign(buf, buf + size);
        }
    }
    // Do not flush here; defer to fsync/release to avoid contention with metadata ops
    return (int)size;
}

static int vix_mkdir(const char *path, mode_t mode) {
    std::cout << "[fuse] mkdir path=" << (path?path:"") << " mode=" << std::oct << mode << std::dec << std::endl;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\",\"mode\":" + std::to_string((long long)mode) + "}";
    if (!h3_post("/fs/mkdir", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_unlink(const char *path) {
    std::cout << "[fuse] unlink path=" << (path?path:"") << std::endl;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\"}";
    if (!h3_post("/fs/unlink", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_rmdir(const char *path) {
    std::cout << "[fuse] rmdir path=" << (path?path:"") << std::endl;
    std::string out;
    std::string in = std::string("{") + "\"path\":\"" + (std::string(path).empty()?"/":path) + "\"}";
    if (!h3_post("/fs/rmdir", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_rename(const char *from, const char *to, unsigned int) {
    std::cout << "[fuse] rename from=" << (from?from:"") << " to=" << (to?to:"") << std::endl;
    std::string out;
    std::string in = std::string("{") + "\"src\":\"" + (std::string(from).empty()?"/":from) + "\",\"dst\":\"" + (std::string(to).empty()?"/":to) + "\"}";
    if (!h3_post("/fs/rename", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *) {
    std::cout << "[fuse] utimens path=" << (path?path:"");
    if (tv) {
        std::cout << " atime=" << tv[0].tv_sec << "." << tv[0].tv_nsec
                  << " mtime=" << tv[1].tv_sec << "." << tv[1].tv_nsec;
    }
    std::cout << std::endl;
    double at = 0.0, mt = 0.0;
    if (tv) {
        at = (double)tv[0].tv_sec + (double)tv[0].tv_nsec / 1e9;
        mt = (double)tv[1].tv_sec + (double)tv[1].tv_nsec / 1e9;
    }
    std::string out;
    std::string in = std::string("{") +
        "\"path\":\"" + (std::string(path).empty()?"/":path) + "\"," +
        "\"atime\":" + std::to_string(at) + "," +
        "\"mtime\":" + std::to_string(mt) + "}";
    if (!h3_post("/fs/utimens", in, out)) return -EIO;
    if (out.find("\"error\"") != std::string::npos) return -EIO;
    return 0;
}

static int vix_statfs(const char *, struct statvfs *st) {
    memset(st, 0, sizeof(struct statvfs));
    std::string out;
    if (h3_get("/fs/statfs", out)) {
        auto get_num = [&](const char *key, unsigned long long defv) -> unsigned long long {
            std::string k = std::string("\"") + key + "\":";
            size_t p = out.find(k);
            if (p == std::string::npos) return defv;
            p += k.size();
            try { return std::stoull(out.substr(p)); } catch (...) { return defv; }
        };
        st->f_bsize = get_num("f_bsize", 4096);
        st->f_frsize = get_num("f_frsize", st->f_bsize);
        st->f_blocks = get_num("f_blocks", 0);
        st->f_bfree = get_num("f_bfree", 0);
        st->f_bavail = get_num("f_bavail", 0);
        st->f_namemax = get_num("f_namemax", 255);
        return 0;
    }
    st->f_bsize = 4096; st->f_frsize = 4096; st->f_blocks = 1024*1024; st->f_bfree = 1024*512; st->f_bavail = 1024*512; st->f_namemax = 255; return 0;
}

// Additional basic ops to avoid -ENOSYS and smooth common flows
static int vix_flush(const char *path, struct fuse_file_info *) {
    std::cout << "[fuse] flush path=" << (path?path:"") << std::endl;
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token};
    if (path) flush_write_locked(path, cfg);
    return 0;
}

static int vix_release(const char *path, struct fuse_file_info *) {
    std::cout << "[fuse] release path=" << (path?path:"") << std::endl;
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token};
    if (path) {
        std::string p(path);
        off_t base = -1;
        std::string data;
        {
            std::lock_guard<std::mutex> lock(g_rw_mutex);
            auto it = g_write_buf.find(p);
            if (it != g_write_buf.end() && !it->second.data.empty() && it->second.base >= 0) {
                base = it->second.base;
                data = std::move(it->second.data);
                g_write_buf.erase(it);
            }
        }
        if (base >= 0 && !data.empty()) {
            // Flush synchronously at close to reduce data loss risk
            std::string out;
            std::string qpath = std::string("/fs/write?path=") + p + "&offset=" + std::to_string((long long)base);
            (void)h3_post_bytes(cfg, qpath, data, out);
        }
    }
    return 0;
}

static int vix_fsync(const char *path, int, struct fuse_file_info *) {
    std::cout << "[fuse] fsync path=" << (path?path:"") << std::endl;
    if (!path) return 0;
    std::string p(path);
    Http3ClientConfig cfg{g_cfg.gateway_host, g_cfg.gateway_port, g_cfg.gateway_token};
    off_t base = -1;
    std::string data;
    {
        std::lock_guard<std::mutex> lock(g_rw_mutex);
        auto it = g_write_buf.find(p);
        if (it != g_write_buf.end() && !it->second.data.empty() && it->second.base >= 0) {
            base = it->second.base;
            data = std::move(it->second.data);
            g_write_buf.erase(it);
        }
    }
    if (base >= 0 && !data.empty()) {
        std::string out;
        std::string qpath = std::string("/fs/write?path=") + p + "&offset=" + std::to_string((long long)base);
        (void)h3_post_bytes(cfg, qpath, data, out);
    }
    return 0;
}

static int vix_getxattr(const char *, const char *, char *, size_t) {
    // No xattr support for now; report no data rather than ENOSYS
    return -ENODATA;
}

static int vix_opendir(const char *path, struct fuse_file_info *) {
    std::cout << "[fuse] opendir path=" << (path?path:"") << std::endl;
    return 0;
}

static int vix_releasedir(const char *path, struct fuse_file_info *) {
    std::cout << "[fuse] releasedir path=" << (path?path:"") << std::endl;
    return 0;
}

static int vix_access(const char *path, int) {
    // Be permissive: allow access checks to pass and rely on open/read/write errors if needed.
    // Returning -EACCES here blocks many standard tools at the root.
    std::cout << "[fuse] access path=" << (path?path:"") << std::endl;
    return 0;
}

// # Check the exact field order in your fuse.h
/// grep -A 50 "struct fuse_operations" /usr/include/fuse/fuse.h | grep -E "(getattr|open|read|write|statfs|readdir|init|create)"

// CORRECT: Use fuse_operations (not fuse3_operations)
static struct fuse_operations vix_ops = {
    // Order must match fuse_operations declaration order
    .getattr = vix_getattr,
    // readlink (unused)
    .mknod  = vix_mknod,
    .mkdir   = vix_mkdir,
    .unlink  = vix_unlink,
    .rmdir   = vix_rmdir,
    // symlink (unused)
    .rename  = vix_rename,
    // link (unused)
    // chmod (unused)
    // chown (unused)
    .truncate= vix_truncate,
    .open    = vix_open,
    .read    = vix_read,
    .write   = vix_write,
    .statfs  = vix_statfs,
    .flush   = vix_flush,
    .release = vix_release,
    .fsync   = vix_fsync,
    // setxattr (unused)
    .getxattr= vix_getxattr,
    // listxattr/removexattr (unused)
    .opendir = vix_opendir,
    .readdir = vix_readdir,
    .releasedir = vix_releasedir,
    // fsyncdir (unused)
    .init    = vix_init,
    // destroy (unused)
    .access  = vix_access,
    .create  = vix_create,
    // lock (unused)
    .utimens = vix_utimens,
    // remaining optional ops left null
};

int main(int argc, char *argv[]) {
    // Parse and strip custom flags BEFORE handing off to FUSE
    g_cfg.gateway_host = "127.0.0.1";
    g_cfg.gateway_port = 9443;

    std::vector<std::string> kept;
    kept.reserve(argc);
    kept.emplace_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--gateway-host" && i + 1 < argc) {
            g_cfg.gateway_host = argv[++i];
            continue;
        }
        if (a.rfind("--gateway-host=", 0) == 0) {
            g_cfg.gateway_host = a.substr(std::string("--gateway-host=").size());
            continue;
        }
        if (a == "--gateway-port" && i + 1 < argc) {
            g_cfg.gateway_port = std::stoi(argv[++i]);
            continue;
        }
        if (a == "--control-host" && i + 1 < argc) {
            g_cfg.control_host = argv[++i];
            g_cfg.use_control = true;
            continue;
        }
        if (a.rfind("--control-host=", 0) == 0) {
            g_cfg.control_host = a.substr(std::string("--control-host=").size());
            g_cfg.use_control = true;
            continue;
        }
        if (a == "--control-port" && i + 1 < argc) {
            g_cfg.control_port = std::stoi(argv[++i]);
            g_cfg.use_control = true;
            continue;
        }
        if (a.rfind("--control-port=", 0) == 0) {
            g_cfg.control_port = std::stoi(a.substr(std::string("--control-port=").size()));
            g_cfg.use_control = true;
            continue;
        }
        if (a == "--control-proxy") {
            g_cfg.control_proxy = true;
            g_cfg.use_control = true;
            continue;
        }
        if (a == "--client-id" && i + 1 < argc) {
            g_cfg.client_id = argv[++i];
            continue;
        }
        if (a.rfind("--client-id=", 0) == 0) {
            g_cfg.client_id = a.substr(std::string("--client-id=").size());
            continue;
        }
        if (a == "--perf" || a == "--perf-cache") { g_cfg.perf_cache = true; continue; }
        if (a == "--gateway-token" && i + 1 < argc) {
            g_cfg.gateway_token = argv[++i];
            continue;
        }
        if (a.rfind("--gateway-token=", 0) == 0) {
            g_cfg.gateway_token = a.substr(std::string("--gateway-token=").size());
            continue;
        }
        if (a.rfind("--gateway-port=", 0) == 0) {
            g_cfg.gateway_port = std::stoi(a.substr(std::string("--gateway-port=").size()));
            continue;
        }
        if (a == "-o" && i + 1 < argc) {
            // Parse -o list; strip gateway_host/gateway_port, keep others
            std::string opts(argv[++i]);
            std::string kept_opts;
            size_t start = 0;
            while (start <= opts.size()) {
                size_t comma = opts.find(',', start);
                std::string item = opts.substr(start, (comma == std::string::npos ? opts.size() : comma) - start);
                if (!item.empty()) {
                    if (item.rfind("gateway_host=", 0) == 0) {
                        g_cfg.gateway_host = item.substr(std::string("gateway_host=").size());
                    } else if (item.rfind("gateway_port=", 0) == 0) {
                        g_cfg.gateway_port = std::stoi(item.substr(std::string("gateway_port=").size()));
                    } else if (item.rfind("gateway_token=", 0) == 0) {
                        g_cfg.gateway_token = item.substr(std::string("gateway_token=").size());
                    } else if (item.rfind("control_host=", 0) == 0) {
                        g_cfg.control_host = item.substr(std::string("control_host=").size());
                        g_cfg.use_control = true;
                    } else if (item.rfind("control_port=", 0) == 0) {
                        g_cfg.control_port = std::stoi(item.substr(std::string("control_port=").size()));
                        g_cfg.use_control = true;
                    } else if (item.rfind("client_id=", 0) == 0) {
                        g_cfg.client_id = item.substr(std::string("client_id=").size());
                    } else if (item.rfind("control_proxy=", 0) == 0) {
                        std::string v = item.substr(std::string("control_proxy=").size());
                        g_cfg.control_proxy = (v == "1" || v == "true" || v == "yes");
                        if (g_cfg.control_proxy) g_cfg.use_control = true;
                    } else if (item == "vix_perf=1" || item == "perf=1" || item == "perf_cache=1") {
                        g_cfg.perf_cache = true;
                    } else {
                        if (!kept_opts.empty()) kept_opts.push_back(',');
                        kept_opts += item;
                    }
                }
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
            if (!kept_opts.empty()) {
                kept.emplace_back("-o");
                kept.emplace_back(kept_opts);
            }
            continue;
        }
        kept.emplace_back(std::move(a));
    }

    // Optional: resolve via control server (only when not proxying via control)
    if (g_cfg.use_control && !g_cfg.control_proxy && !g_cfg.client_id.empty()) {
        (void)resolve_gateway_from_control();
    }
    // Optional: proxy all traffic via control server
    if (g_cfg.control_proxy && !g_cfg.control_host.empty()) {
        g_cfg.gateway_host = g_cfg.control_host;
        g_cfg.gateway_port = g_cfg.control_port;
        std::cout << "vix_cpp_fuse: using control proxy " << g_cfg.gateway_host << ":" << g_cfg.gateway_port << " for client_id=" << g_cfg.client_id << std::endl;
    }

    std::cout << "vix_cpp_fuse: gateway " << g_cfg.gateway_host << ":" << g_cfg.gateway_port << std::endl;

    // Build argv for FUSE
    std::vector<char*> argv2;
    argv2.reserve(kept.size());
    for (auto &s : kept) argv2.push_back(const_cast<char*>(s.c_str()));
    int argc2 = (int)argv2.size();
    return fuse_main(argc2, argv2.data(), &vix_ops, nullptr);
}

