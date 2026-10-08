# MeshDrive

MeshDrive is a zero-trust, self-hosted private storage and file infrastructure platform designed to help users and teams reclaim their existing hardware to build secure, private, and unlimited cloud storage. By turning idle devices (such as an old laptop, a spare server, or a Raspberry Pi) into sovereign storage nodes, MeshDrive eliminates traditional cloud storage subscription costs while retaining absolute privacy and local performance.

Integrated tightly with modern networking layers like the Vix Gateway (leveraging HTTP/3 over QUIC and seamless FUSE clients), MeshDrive makes remote or distributed storage feel as fast and immediate as a local drive.

### Key Features & Capabilities

1. Zero-Trust & Privacy-First Architecture: Built with a zero-knowledge approach. Your device holds the encryption keys, meaning data is end-to-end encrypted and never inspected or stored by third parties.

2. Hardware Reclamation: Transform any old or idle machine into a high-performance private storage vault without investing in expensive dedicated NAS hardware.

3. QUIC & HTTP/3 Enabled Performance: Utilizes modern transport protocols (QUIC) for fast multiplexing, low latency, and resilient performance even across flaky Wi-Fi connections or long distances.

4. POSIX & S3-Compatible APIs: Provides standard-compliant endpoints (like S3-compatible blob storage and POSIX filesystem operations) for seamless integration with pre-built or custom applications.

5. Offline-First & Local LAN Resiliency: Designed to operate seamlessly on local networks even when the external internet connection drops, synchronizing and serving files locally until WAN uplinks return.

6. Chunked & Resumable Uploads: Efficiently handles large file transfers (50GB+) with content-addressed chunking, deduplication, and automatic resumption if interrupted.

7. Robust Security Standards: Features modern cryptographic ciphers (such as ChaCha20-Poly1305 or AES-256-GCM), Curve25519 key exchange, built-in TLS with local CA flows, and comprehensive role-based access control (RBAC).

### Architecture & Deployment

1. Single-Binary Simplicity: Distributed as lightweight, portable executables requiring minimal configuration.

2. Flexible Mounting: Can be mounted as a standard local directory via FUSE clients, allowing any desktop application to open, edit, and save remote files natively without manual downloads or sync delays.

