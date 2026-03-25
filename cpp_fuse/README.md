# VIX C++ FUSE Client (skeleton)

This is a minimal scaffold for a future high-performance C++ FUSE client that speaks the VIX /fs API over QUIC.

- Build prerequisites: libfuse3-dev, cmake, a C++17 compiler.
- Networking/QUIC stack TBD (e.g., quiche, msquic, ngtcp2). For now, the skeleton stubs out RPCs.

## Build
```
mkdir -p build && cd build
cmake .. && make -j
cmake ../cpp_fuse && make -j

cmake -DUSE_QUICHE=ON -DQUICHE_INCLUDE_DIR=src/ -DQUICHE_LIB=src/ .

cmake -DUSE_QUICHE=ON -DQUICHE_INCLUDE_DIR=/home/ext_hardik13_patel_ril_com/cpp_fuse/cpp_fuse/src/ -DQUICHE_LIB=/home/ext_hardik13_patel_ril_com/cpp_fuse/build/CMakeFiles/vix_cpp_fuse.dir/src/transport_quiche.cpp.o ../cpp_fuse

cmake -DUSE_QUICHE=ON -DQUICHE_INCLUDE_DIR=/home/ext_hardik13_patel_ril_com/cpp_fuse/cpp_fuse/src/ -DQUICHE_LIB=/home/ext_hardik13_patel_ril_com/cpp_fuse/cpp_fuse/src/ ../cpp_fuse

cmake -DUSE_QUICHE=ON -DQUICHE_INCLUDE_DIR=/home/ext_hardik13_patel_ril_com/cpp_fuse/quiche/quiche/include/ -DQUICHE_LIB=/home/ext_hardik13_patel_ril_com/cpp_fuse/quiche/target/release/libquiche.a  -DQUICHE_EXTRA_LIBS="/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so" ../cpp_fuse

cmake -DUSE_QUICHE=ON -DUSE_PROTOBUF=ON \
  -DQUICHE_INCLUDE_DIR=/home/ext_hardik13_patel_ril_com/cpp_fuse/quiche/quiche/include \
  -DQUICHE_LIB=/home/ext_hardik13_patel_ril_com/cpp_fuse/quiche/target/release/libquiche.a \
  -DQUICHE_EXTRA_LIBS="$(pkg-config --libs quiche 2>/dev/null || echo '/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so')" \
  ../cpp_fuse

cmake -DUSE_QUICHE=ON -DUSE_PROTOBUF=ON \
  -DQUICHE_INCLUDE_DIR=/home/ext_hardik13_patel_ril_com/quiche/quiche/include \
  -DQUICHE_LIB=/home/ext_hardik13_patel_ril_com/quiche/target/release/libquiche.a \
  -DQUICHE_EXTRA_LIBS="$(pkg-config --libs quiche 2>/dev/null || echo '/usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so')" \
  ../cpp_fuse

cmake -DUSE_QUICHE=ON ../cpp_fuse
make -j

cpack -G DEB
cpack -G RPM
```

## Run
```
sudo ./vix_cpp_fuse <mountpoint> --gateway-host <host> --gateway-port 9443

sudo ./vix_cpp_fuse /home/ext_hardik13_patel_ril_com/vx_data --gateway-host 10.18.0.42 --gateway-port 9443

sudo ./vix_cpp_fuse -o gateway_host=10.18.0.42 -o gateway_port=9443 /home/ext_hardik13_patel_ril_com/vx_data

sudo ./vix_cpp_fuse -o gateway_host=10.18.0.42 -o gateway_port=9443 /home/ext_hardik13_patel_ril_com/vx_data > /tmp/vix_cpp_fuse.log 2>&1

sudo ./vix_cpp_fuse --gateway-host 10.18.0.42 --gateway-port 9443 --gateway-token dev -f -d -o --perf /home/ext_hardik13_patel_ril_com/vx_data

sudo bash -c 'stdbuf -oL -eL ./vix_cpp_fuse -f -d -o gateway_host=10.18.0.42 -o gateway_port=9443 /home/ext_hardik13_patel_ril_com/vx_data |& tee /tmp/vix_cpp_fuse.log'

sudo ./vix_cpp_fuse -f -s -d \
      -o gateway_host=10.18.0.42 -o gateway_port=9443 -o gateway_token=dev \
      /home/ext_hardik13_patel_ril_com/vx_data

sudo ./vix_cpp_fuse -f -d \
      -o gateway_host=10.18.0.42 -o gateway_port=9443 -o gateway_token=dev \
      /home/ext_hardik13_patel_ril_com/vx_data

sudo ./vix_cpp_fuse -f -d -o vix_perf=1 \
  --gateway-host 10.18.0.42 --gateway-port 9443 -o gateway_token=dev /home/ext_hardik13_patel_ril_com/vx_data

sudo ./vix_cpp_fuse --gateway-host 10.18.0.42 --gateway-port 9443 -f -d /home/ext_hardik13_patel_ril_com/vx_data
```
#########################


sudo ./vix_cpp_fuse -f -d \
      -o gateway_host=10.18.0.42 -o gateway_port=9443 -o gateway_token=dev \
      /home/ext_hardik13_patel_ril_com/vx_data

sudo ./vix_cpp_fuse -f -d  -o gateway_token=dev \
  /home/ext_hardik13_patel_ril_com/vx_data \
  --control-host 10.18.0.2 --control-port 9444 \
  --client-id lakehouse-dev --control-proxy

sudo ./vix_cpp_fuse -f -d  \
  /home/ext_hardik13_patel_ril_com/vx_data \
  --control-host 10.18.0.2 --control-port 9444 \
  --client-id lakehouse-dev --control-proxy \
  --gateway-token dev

sudo ./vix_cpp_fuse -f -d  \
  /home/ext_hardik13_patel_ril_com/vx_data \
  --control-host cloud.vistrix.in --control-port 443 \
  --client-id lakehouse-dev --control-proxy \
  --gateway-token dev

## quich build with extra flags

git clone --recurse-submodules --branch master https://github.com/cloudflare/quiche.git
cd quiche
git fetch --all --tags

git checkout 0.24.6

rustup/cargo version: 1.90.0 --> supports h3

cargo build --release --features ffi,h3,pkg-config-meta
cargo build --release --features ffi,pkg-config-meta,qlog


cargo build --release --features ffi,pkg-config-meta


## IOPS test with fio

fio --name=random-read --directory=/home/ext_hardik13_patel_ril_com/vx_data --ioengine=libaio \
--iodepth=32 --rw=randread --bs=4k --direct=1 --size=1G --numjobs=4 \
--runtime=60 --group_reporting

### Prepare test file
dd if=/dev/zero of=/home/ext_hardik13_patel_ril_com/vx_data/output.bin bs=1M count=1024
dd if=/dev/zero of=./test_10.bin bs=1M count=10

dd if=/dev/zero of=./test_640k.bin bs=64k count=10 oflag=sync

dd if=/dev/zero of=./test_640M.bin bs=64k count=1000 oflag=sync


strace -f -e trace=network -p 10703
strace -f -tt -e trace=network,ppoll,epoll_wait,select -p 39492

### Random read 

fio --name=rr \
  --filename=/home/ext_hardik13_patel_ril_com/vx_data/test.bin \
  --ioengine=psync --iodepth=1 \
  --rw=randread --bs=4k \
  --numjobs=4 --time_based=1 --runtime=60 --group_reporting

## Performance roadmap

The client now pools a single QUIC + HTTP/3 connection (30–60s idle) and uses JSON payloads.

- Immediate (implemented): Connection pooling with 30–60s idle timeout (reduces handshake/setup overhead)
- Short-term: Switch metadata/data RPCs from JSON to Protocol Buffers (binary payloads)
- Medium-term: Request batching/coalescing for small I/O (merge adjacent reads/writes)
- Long-term: Adaptive strategies based on observed load (tune batch size, concurrency)

Expected improvements (indicative):
- Connection pooling: 3–5x IOPS improvement
- Binary protocol: additional 2–3x
- Batching: additional 2–4x for small ops

### Random write

fio --name=rw \
  --filename=/home/ext_hardik13_patel_ril_com/vx_data/test.bin \
  --ioengine=psync --iodepth=1 \
  --rw=randwrite --bs=4k \
  --numjobs=4 --time_based=1 --runtime=60 --group_reporting


### Command to run on docker via http3

docker run --rm compscidr/curl-http3-quic --http3 -k https://10.18.0.42:9443/fs/statfs

docker run --rm compscidr/curl-http3-quic --http3 -k -H "x-client-id: lakehouse-dev" -H "Authorization: Bearer dev" https://10.18.0.2:9444/fs/statfs

docker run --rm compscidr/curl-http3-quic --http3 -k \
  'https://10.18.0.2:9444/resolve?client_id=lakehouse-dev'

docker run --rm compscidr/curl-http3-quic --http3 -k https://10.18.0.2:9444/status

docker run --rm compscidr/curl-http3-quic --http3 -k \
  -H 'x-client-id: lakehouse-dev' \
  -H 'Authorization: Bearer dev' \
  -H 'Accept: application/x-protobuf' \
  'https://10.18.0.2:9444/fs/readdir?path=/'

docker run --rm compscidr/curl-http3-quic --http3 -k \
  -H 'x-client-id: lakehouse-dev' \
  -H 'Authorization: Bearer dev' \
  -H 'Content-Type: application/json' \
  -d '{"path":"/"}' \
  'https://10.18.0.2:9444/fs/readdir'

      docker run --rm compscidr/curl-http3-quic --http3 -k \
        -H 'x-client-id: lakehouse-dev' \
        -H 'Authorization: Bearer dev' \
        'https://10.18.0.2:9444/fs/read?path=/&offset=0&size=64'