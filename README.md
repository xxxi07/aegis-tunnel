# AEGIS-Tunnel

A lightweight secure tunnel based on **AEGIS-128** authenticated encryption and **X25519 ECDH**, supporting both TUN VPN and TCP proxy modes with automatic crypto backend selection (x86 AES-NI / ARM Crypto / Pure C).

## Overview

AEGIS-Tunnel is a minimal encrypted tunnel tool providing:

- **TUN VPN mode**: WireGuard-style four-phase workflow (keygen → peer add → create tun → start tun)
- **Proxy mode**: Encrypted TCP tunnel forwarding (similar to Stunnel / SSH -L)
- **Asymmetric handshake**: X25519-based 3-DH key exchange with multi-peer management
- **Automatic crypto backend selection**: x86 AES-NI (~92x speedup) > ARM Crypto > ARM NEON > Pure C

## Features

- **AEGIS-128 AEAD**: CAESAR competition winner, being standardized by IETF CFRG
- **X25519 asymmetric handshake**: 3-DH key exchange + timestamp replay protection, multi-peer support
- **TUN virtual interface**: Layer 3 VPN supporting full-tunnel / split-tunnel / multi-subnet routing
- **fwmark policy routing**: Automatically marks tunnel TCP connections to prevent routing loops
- **Multi-platform acceleration**: x86_64 AES-NI / aarch64 ARM Crypto / ARM NEON / Pure C
- **WireGuard-style configuration**: INI file management with `peer add/delete/list` subcommands
- **Auto-cleanup**: Automatically removes routing rules and TUN device on Ctrl+C
- **~1,500 lines of C99** (main + modes + config management), easy to audit and customize

## Project Structure

```
src/
├── main.c              # Entry point: argument parsing + mode dispatch (495 lines)
├── main.h              # Global variables and function declarations
├── config_mgmt.c/h     # Config management: keygen / peer add/delete / create tun
├── mode_common.c/h     # Shared mode code: multi-peer handshake
├── mode_psk.c          # Proxy mode (TCP tunnel)
├── mode_tun.c          # TUN VPN mode
├── crypto/             # AEGIS-128 encryption
│   ├── aegis.c/h       # Core implementation + runtime backend selection
│   ├── x86/            # x86 AES-NI acceleration
│   └── neon/           # ARM Crypto + NEON acceleration
├── protocol/           # Network protocol
│   ├── handshake.c/h   # X25519 3-DH handshake + key confirmation + rekey
│   ├── ecdh.c/h        # X25519 key exchange (OpenSSL EVP)
│   ├── frame_reader.c/h # TCP stream frame reader
│   └── keyfile.c/h     # Key file I/O
├── tunnel/             # Tunnel engine
│   ├── tunnel.c/h      # poll() event loop + frame encrypt/decrypt
│   ├── tun.c/h         # TUN device management + routing + iptables
│   └── threadpool.c/h  # Thread pool (optional; fork by default)
├── proxy/              # SOCKS5 proxy (optional)
│   └── socks5.c/h
└── util/               # Utilities
    ├── util.c/h        # hex_dump / random_bytes / secure_memzero
    ├── iniconfig.c/h   # WireGuard-style INI parser
    ├── config.c/h      # Legacy key=value compat parser (unused)
    └── log.c/h         # Logging module
```

## Quick Start

### Dependencies

- GCC >= 9.0 (or Clang >= 10.0)
- OpenSSL >= 1.1.1 (libssl-dev, for X25519 + SHA256)
- Linux (TUN mode requires `/dev/net/tun`, `ip` command, `iptables`)

### Build

```bash
# Quick build (Makefile)
make

# Or with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# ARM cross-compilation (Raspberry Pi, etc.)
make                    # Makefile auto-detects aarch64
```

### TUN VPN Mode (Four-Phase Workflow)

```bash
# Phase 1: Generate keypair + base config
./aegis-tunnel keygen

# Phase 2: Exchange public keys (both sides)
./aegis-tunnel peer add <peer-name> <peer-64-char-hex-public-key>

# Phase 3: Generate TUN configuration
./aegis-tunnel create tun -server    # Server side
./aegis-tunnel create tun -client    # Client side

# Phase 4: Start VPN (requires root)
sudo ./aegis-tunnel start tun -server
sudo ./aegis-tunnel start tun -client
```

**Client** `aegis-client.conf` key settings:

```ini
[Peer]
Endpoint = server-ip:9000    # ← Change to server real address
AllowedIPs = 0.0.0.0/0       # Full tunnel; or 10.0.0.0/24 for split tunnel
```

### Proxy Mode (Encrypted TCP Tunnel, Legacy Compatible)

```bash
# Server: decrypt and forward to 127.0.0.1:8080
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server

# Client: listen locally on 9000, encrypt and send to server
./aegis-tunnel -l 9000 -r server-ip:9000 -m client
```

### Management Commands

```bash
./aegis-tunnel status             # View keys and peer status
./aegis-tunnel peer list          # List known peers
./aegis-tunnel peer delete <name> # Remove a peer
sudo ./aegis-tunnel tun down      # Manually remove TUN device and routes
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-l <port>` | Local listen port | `-l 9000` |
| `-r <host:port>` | Remote target address | `-r 1.2.3.4:9000` |
| `-m <mode>` | Run mode | `-m server` or `-m client` |
| `-T <ip/prefix>` | TUN VPN CIDR | `-T 10.0.0.1/24` |
| `-R <network>` | TUN route (AllowedIPs) | `-R 10.0.0.0/24` |
| `-W <iface>` | WAN interface for NAT | `-W eth0` |
| `-P <file>` | Private key file path | `-P /path/to/private.key` |
| `-Q <hex\|file>` | Peer public key | `-Q a1b2...` or `-Q peer.pub` |
| `-c <file>` | Config file path | `-c aegis.conf` |
| `-K <sec>` | Keepalive interval | `-K 30` |
| `-t <sec>` | Handshake timeout | `-t 10` |
| `-x <max>` | Max connections | `-x 64` |
| `-v` | Verbose logging | — |
| `-h` | Show help | — |

## Protocol

### Frame Format

```
 0      1      2-3         4...(N+3)      (N+4)...(N+19)
+------+------+--------+--------//----+--------//--------+
| type | flags| length |   payload     |    tag (16 B)    |
|  1   |  1   |  2 BE  |  0..65535 B   |                  |
+------+------+--------+--------//----+--------//--------+
```

- Frame header (4 bytes) passed as AEGIS-128 associated data (AD)
- 16-byte authentication tag covers header + ciphertext
- Nonce = little-endian 64-bit counter || 8 zero bytes

### Asymmetric Handshake (X25519 3-DH)

```
Client                                        Server
  |                                               |
  |── handshake_init(eph_pub_c, ts_c) ──────────▶|
  |     AEGIS-encrypted, key = SHA256(ee||es||"init") |
  |                                               | Verify timestamp, try all known peer keys
  |◀─ handshake_resp(eph_pub_s, ts_s) ──────────│
  |     AEGIS-encrypted, key = SHA256(shared||"resp") |
  |                                               |
  |◀══ KEY_CONFIRM ─══════════════════════════════│ (server sends first)
  |══▶ KEY_CONFIRM ─══════════════════════════════▶| (client verifies)
  |                                               |
  |══▶ DATA (encrypted traffic) ─════════════════▶|
  |◀══ DATA (encrypted traffic) ─═════════════════│
```

Shared secret: `SHA256(ee || es || se || "shared")`, where:
- `ee` = ephemeral private key × peer ephemeral public key
- `es` = own static private key × peer ephemeral public key
- `se` = ephemeral private key × peer static public key

## Testing

```bash
make test           # Run all tests at once

# Or run individually
./test-aegis        # AEGIS-128 algorithm: 13 tests
./test-tunnel       # Frame protocol + asymmetric handshake: 8 tests
./e2e-test          # End-to-end handshake + encrypt/decrypt: 2 tests
./bench-aegis       # Performance benchmarks
```

## Performance

| Platform | Pure C | x86 AES-NI | ARM Crypto | ARM NEON |
|----------|--------|-----------|------------|----------|
| x86_64 | ~110 MB/s | **~9500 MB/s** | — | — |

| aarch64 | ~80 MB/s | — | ~120 MB/s | ~3900 MB/s |

## Security

- **Encryption**: AEGIS-128, 128-bit security level
- **Key exchange**: X25519 3-DH, fresh ephemeral keys per session (forward secrecy)
- **Authentication**: 128-bit tag, 2^-128 forgery probability
- **Replay protection**: Handshake timestamp ±60s window + per-direction monotonic nonce counters
- **Timing safety**: Constant-time tag comparison
- **Memory safety**: Sensitive data (keys, nonces, shared secrets) zeroed immediately via `secure_memzero()`

## Documentation

- [Protocol Specification](docs/protocol.md)
- [Testing and Usage Guide](docs/testing.md)
- [Known Issues and Improvement Plan](docs/known-issues.md)

## License

MIT License — see [LICENSE](LICENSE)

## References

- [AEGIS Specification (CAESAR submission)](https://competitions.cr.yp.to/round3/aegisv11.pdf)
- [IETF CFRG AEGIS Draft](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead)
- [WireGuard Protocol Design](https://www.wireguard.com/papers/wireguard.pdf)
