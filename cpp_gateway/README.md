## VIX C++ QUIC/HTTP3 Gateway (quiche-based)

This is a minimal C++17 HTTP/3 (QUIC) gateway that mirrors the Python aioquic gateway’s filesystem endpoints:
- GET /health
- GET/POST /fs/stat
- GET/POST /fs/readdir
- GET/POST /fs/read (supports application/octet-stream)
- POST /fs/write (supports application/octet-stream)
- POST /fs/truncate
- POST /fs/utimens
- GET/POST /fs/statfs

It uses the quiche C FFI for QUIC + HTTP/3.

### Prereqs
- A modern C++17 compiler, CMake
- OpenSSL (libssl, libcrypto)
- Rust toolchain (cargo) to build quiche with ffi,h3

### Build quiche (once)
```bash
git clone https://github.com/cloudflare/quiche.git
cd quiche
cargo build --release --features ffi,h3,pkg-config-meta
```
Artifacts:
- quiche/include/      # QUICHE headers
- target/release/libquiche.a

### Build the C++ gateway
```bash
cd vix_package/cpp_gateway
mkdir -p build && cd build
cmake -DUSE_QUICHE=ON -DUSE_PROTOBUF=ON \
  -DQUICHE_INCLUDE_DIR=~/cpp_gateway/quiche/quiche/include \
  -DQUICHE_LIB=~/cpp_gateway/quiche/quiche/target/release/libquiche.a \
  -DQUICHE_EXTRA_LIBS="$(pkg-config --libs quiche 2>/dev/null || echo '/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so')" \
  ../cpp_gateway
make -j
```

```bash
cmake -DUSE_QUICHE=ON -DUSE_PROTOBUF=ON \
  -DQUICHE_INCLUDE_DIR=~/cpp_gateway/quiche/quiche/include \
  -DQUICHE_LIB=~/cpp_gateway/quiche/target/release/libquiche.a \
  -DQUICHE_EXTRA_LIBS="$(pkg-config --libs quiche 2>/dev/null || echo '/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so')" \
  ../cpp_gateway
make -j
```

If pkg-config for quiche is not available, ensure `QUICHE_EXTRA_LIBS` points to your system `libssl.so` and `libcrypto.so`.

### Run
Generate or provide a TLS cert/key (PEM):
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout quic_key.pem -out quic_cert.pem -subj "/CN=localhost" -days 3650
```

Start the gateway:
```bash
./vix_cpp_gateway \
  --host 0.0.0.0 --port 9443 \
  --storage /opt/vxstorage/lucifer \
  --cert ../quic_cert.pem --key ../quic_key.pem \
  --token dev \
  --verbose
```

./vix_cpp_gateway \
  --host 0.0.0.0 --port 9443 \
  --storage /opt/vxstorage/lucifer \
  --cert ~/vxapi/quic_cert.pem --key ~/vxapi/quic_key.pem \
  --token dev \
  --read-ahead-bytes 1048576 --read-cache-bytes 268435456
  --verbose

./vix_cpp_gateway \
  --host 0.0.0.0 --port 9443 \
  --storage /opt/vxstorage/lucifer \
  --cert ~/vxapi/quic_cert.pem --key ~/vxapi/quic_key.pem \
  --token dev \
  --read-ahead-bytes 1048576 \
  --enable-control --control-host 10.18.0.2 --control-port 9444 --client-id lakehouse-dev

./vix_cpp_gateway \
  --host 0.0.0.0 --port 9443 \
  --storage /opt/vxstorage/lucifer \
  --cert ~/vxapi/quic_cert.pem --key ~/vxapi/quic_key.pem \
  --token dev \
  --read-ahead-bytes 1048576 \
  --enable-control --control-host 152.67.1.46 --control-port 9444 --client-id lakehouse-dev --verbose

./vix_cpp_gateway \
  --host 0.0.0.0 --port 9443 \
  --storage /opt/vxstorage/lucifer \
  --cert ~/vxapi/quic_cert.pem --key ~/vxapi/quic_key.pem \
  --token dev \
  --read-ahead-bytes 1048576 \
  --enable-control --control-host cloud.vistrix.in --control-port 443 --client-id lakehouse-dev --verbose

Optional flags:
- `--flat`                operate directly on storage root (no bucket/key)
- `--durable-writes`      fsync after each write batch (slower, safer)
- `--read-ahead-bytes N`  read-ahead base for /fs/read (default 262144)
 - `--token TOKEN`         require `Authorization: Bearer TOKEN` on every request
 - `--verbose`             print detailed request/response logs

### Notes
- Flow-control windows are increased for large transfers:
  - initial_max_data = 128 MiB
  - initial_max_stream_data_bidi_local/remote = 32 MiB
  - initial_max_streams_bidi = 1024, uni = 256
- This is a minimal, single-threaded event loop using `poll()` on a UDP socket.
- QLOG is not wired in this minimal version; use packet capture or instrument as needed.


docker run --rm compscidr/curl-http3-quic --http3 -k https://10.18.0.42:9443/fs/statfs

{"model": "qwen2.5-coder:7b-128k", "from":"qwen2.5-coder:7b", "parameters": "128000"}

