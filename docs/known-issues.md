# AEGIS-Tunnel Known Issues and Improvement Plan

## 1. Code Structure Issues

### 1.1 main.c Bloat ✅ Resolved

Split into `main.c` (495 lines: argument parsing + mode dispatch), `config_mgmt.c` (448 lines: config management subcommands), and `mode_common.c` (17 lines: shared handshake logic).

### 1.2 Duplicate Secure Cleanup in handshake.c ✅ Resolved

Unified via `goto out` pattern; secure_memzero calls reduced from 62 to 16.

### 1.3 Duplicate try_handshake_server in mode_psk.c / mode_tun.c ✅ Resolved

Extracted to `src/mode_common.c`; both modules share the same implementation.

### 1.4 Thread Pool Compiled but Unused ✅ Build Option Added

Makefile includes `-DWITH_THREADPOOL` build option (commented out by default). Uncomment to enable.

---

## 2. Naming Inconsistencies ✅ Resolved

| Issue | Before | After |
|-------|--------|-------|
| Timeout functions | `set_to()` / `set_timeout()` / `set_socket_timeout()` | Unified: `recv_all()` uses `poll()` timeout; SO_RCVTIMEO removed |
| Hash functions | `H()` / `sha256_or_die()` | Unified: `sha256_h()` |
| Prefixes | `asym_` / `asymmetric_` | Unified: `asym_` (internal static functions) |
| Constants | `tofu_` / `TOFU_` | Constants upper-case, functions lower-case |

---

## 3. Security Concerns

### 3.1 Hardcoded nonce=1 in TOFU Key Exchange ✅ Resolved

`tofu_exchange_keys()` now accepts a `uint64_t *nonce_ctr` parameter, incremented after each use.

### 3.2 system() Usage for iptables in TUN Mode ✅ Partially Resolved

`tun_set_nat()` and `tun_allow_forward()` now use `fork() + execvp()`. `tun_exec_script()` now uses `fork() + execl("/bin/sh", ...)` explicitly, consistent with the iptables approach.

### 3.3 PSK Visible in Process List

When using `-k <hex>` to pass a PSK, it appears in `/proc/<pid>/cmdline` and is readable by other users on the same host.

**Recommendation**: Always prefer the `-f <file>` method. Future versions could accept input via pipe or environment variable.

### 3.4 SO_RCVTIMEO Cross-Platform Compatibility ✅ Resolved

`SO_RCVTIMEO` returned spurious EAGAIN on fwmark'd sockets on some Linux kernel versions. Replaced with `poll()`: `recv_all()` now only calls `recv()` after `poll()` confirms POLLIN.

---

## 4. Incomplete Features

### 4.1 Asymmetric Handshake Could Not Be Used Independently ✅ Resolved

Now defaults to X25519 3-DH asymmetric handshake. PSK is only used as additional re-keying material and is auto-derived from session keys when not explicitly provided.

### 4.2 SOCKS5 Lacks IPv6 Support

`socks5.c` handles only ATYP=0x01 (IPv4) and ATYP=0x03 (DOMAIN); ATYP=0x04 (IPv6) is unsupported.

### 4.3 No Log File Output

All log output goes to stderr; file output and log rotation are not supported.

### 4.4 Client Connection Retry Implemented ✅ Resolved

Both `mode_psk.c` and `mode_tun.c` client modes implement exponential backoff reconnection (1s → 2s → 4s → ... → 30s max).

---

## 5. Test Coverage Gaps

### 5.1 No Fuzz Testing

The frame parser `frame_reader.c` is the TCP stream entry point and lacks fuzz testing. Maliciously crafted packets could cause buffer overflows.

**Recommendation**: Use AFL/libFuzzer against `frame_reader_try_next()`.

### 5.2 No Stress Testing

No concurrent connection, large data volume, or long-running stability tests.

### 5.3 ARM NEON Never Tested on Hardware ✅ Verified on Raspberry Pi

Both accelerated paths under `src/crypto/neon/` (Plain NEON and ARM Crypto) have been validated on real ARM hardware. x86_64 ↔ aarch64 cross-platform handshake has passed testing.

### 5.4 iniconf / keyfile Modules Lack Unit Tests 🆕

The INI config parser (`iniconfig.c`) and key file I/O (`keyfile.c`) modules lack independent unit tests.

---

## 6. Dependency Issues

### 6.1 OpenSSL EVP API

The project has a hard dependency on OpenSSL (SHA256, X25519). It cannot compile on embedded systems without OpenSSL.

**Recommendation**: Future versions could integrate a lightweight alternative (e.g., Monocypher, TweetNaCl).

### 6.2 Linux-Specific APIs

TUN mode (`/dev/net/tun`), `SO_MARK` (fwmark), `ip route`/`iptables` commands, etc. are Linux-specific and cannot compile on macOS/BSD.

---

## 7. Makefile vs. CMakeLists.txt Inconsistencies 🆕

| Difference | Makefile | CMakeLists.txt | Status |
|-----------|----------|----------------|--------|
| AES-NI compilation | Compiled directly into main | Linked as static library | ℹ️ |
| ARM NEON (AEGIS_HAVE_NEON) | ✅ Added | ✅ Present | ✅ |
| HAVE_EXPLICIT_BZERO | ❌ Missing | ✅ Present | ℹ️ |
| -lpthread | Always linked | Only for test-tunnel | ℹ️ |
| ARM -march=armv8-a+crypto | Global CFLAGS | Crypto target only | ℹ️ |

---

## 8. Improvement Priorities

| Priority | Issue | Impact |
|----------|-------|--------|
| 🔴 High | — None at this time — | — |
| 🟡 Medium | SOCKS5 lacks IPv6 | Incomplete feature |
| 🟡 Medium | No log file output | Operations difficulty |
| 🟡 Medium | iniconf/keyfile lack tests | Potential regressions |
| 🟡 Medium | Makefile/CMake behavior differences | ARM build variations |
| 🟢 Low | No fuzz testing | Security boundary |
| 🟢 Low | No stress testing | Stability unknown |
| 🟢 Low | OpenSSL dependency | Embedded deployment constraints |
