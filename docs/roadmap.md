# AEGIS-Tunnel Production Readiness Roadmap

## Phase 1: Protocol Security Hardening ✅ COMPLETED

### 1.1 Per-IP Handshake Rate Limiting (Anti-DoS) ✅

Prevents ECDH computation exhaustion by limiting handshake attempts
per source IP to 5 per 60-second window. Rejects connections before
the expensive ECDH calculation.

```
Implementation: src/mode_common.c → handshake_rate_check()
Integrated in: mode_psk_server, mode_tun_server, mode_socks5_server
Limits: 5 handshakes / 60s / IP, ring-buffer eviction for >32 IPs
```

### 1.2 Periodic Session Re-Key ✅

Rotates session keys every 120 seconds (WireGuard-style). Uses the
existing ECDH re-key mechanism that was previously disabled.

```
Implementation: tunnel_init sets rekey_sec = 120 by default
Previous: all mode files overrode with rekey_sec = 0 (disabled)
Mechanism: ECDH key exchange → new session keys → nonces reset to 0
```

### 1.3 Handshake Replay Hardening ✅

Sliding-window replay detection using (timestamp, ephemeral_pubkey_prefix)
pairs. Prevents exact replay of a captured handshake init message within
the ±60 second timestamp window.

```
Implementation: src/protocol/handshake.c → is_replay()
Key: (int64_t timestamp, uint64_t eph_pub_prefix), 128 slots
Different ephemeral keys at the same timestamp are allowed (distinct handshakes)
```

---

## Phase 2: Operational Readiness

### 2.1 Daemon Mode + Pidfile

**Status**: Planned
**Effort**: 2 days

```
$ aegis-tunnel start tun -server --daemon --pidfile /run/aegis.pid
$ aegis-tunnel stop --pidfile /run/aegis.pid
$ aegis-tunnel reload  # SIGHUP → reload aegis.conf, hot-add peers
```

- `fork()` + `setsid()` for daemonization
- Write PID file on startup, check for existing instance
- `SIGHUP`: reload config without dropping connections
- `SIGTERM`: graceful shutdown + PostDown execution

### 2.2 Logging System Upgrade

**Status**: Planned
**Effort**: 1 day

- Log levels: ERROR / WARN / INFO / DEBUG
- Output targets: stderr | syslog | file (selectable via CLI)
- File rotation by size (default 10 MB) or daily
- Affects: `src/util/log.c` (~100 lines expansion)

### 2.3 Configuration Validation

**Status**: Planned
**Effort**: 1 day

- Validate required fields after `keygen` (PrivateKey, at least one [Peer])
- Validate hex key format and length on `peer add`
- Pre-flight check before `start tun` (Address format, Endpoint format)
- Affects: `src/config_mgmt.c` → new `validate_config()` function

---

## Phase 3: TCP-over-TCP Optimization

### 3.1 TCP Connection Pooling (Multipath)

**Status**: Planned
**Effort**: 3 days
**Priority**: High (addresses TCP head-of-line blocking)

```
Current:  All tunnel traffic → single TCP connection
Proposed: N parallel TCP connections (default 4)
          Packets distributed by (src_ip, dst_ip, sport, dport) hash
```

- Client opens N TCP connections to server
- Each connection: independent handshake + nonce space
- TUN outbound: hash 5-tuple → connection index
- One connection's retransmission does not block others
- `REKEY` frames synchronized across all connections
- Affects: `src/mode_tun.c` → new `multipath` mode

### 3.2 UDP Transport Mode (Alternative to TCP)

**Status**: Planned (long-term)
**Effort**: 1 week
**Priority**: Medium

```
Rationale: TCP congestion control inside TCP tunnel creates
          nested control loops with unpredictable behavior
```

- New `src/mode_tun_udp.c`
- UDP datagrams + application-layer retransmission
- Simple congestion control (similar to WireGuard/QUIC)
- Keepalive as implicit ACK
- Eliminates TCP-over-TCP head-of-line blocking entirely

---

## Phase 4: Cross-Platform Support

### 4.1 macOS / BSD Port

**Status**: Planned
**Effort**: 3 days

- macOS: `/dev/tun` (different ioctl from Linux `/dev/net/tun`)
- BSD: similar to macOS
- Routing: `route(8)` instead of `ip(8)`
- Firewall: `pfctl` instead of `iptables`
- Encapsulate in `src/tunnel/tun_darwin.c` (~200 lines)

### 4.2 Embedded Lightweight Mode

**Status**: Planned
**Effort**: 2 days

```
$ make MONOCYPHER=1
```

- Replace OpenSSL with Monocypher (~1500 lines C, X25519 + SHA-512)
- Conditional compilation: `#ifdef USE_MONOCYPHER`
- Target: static binary < 500 KB
- Suitable for: OpenWrt, Yocto, Buildroot

---

## Phase 5: Testing and Verification

### 5.1 Formal Protocol Verification

**Status**: Planned
**Effort**: 1 week

- Model AEGIS-128 as black-box AEAD in ProVerif/Tamarin
- Model 3-DH handshake flow
- Verify: key secrecy, mutual authentication, forward secrecy, replay resistance
- Deliverable: `docs/formal-verification.md` + `.pv` model files

### 5.2 Stress Test Suite

**Status**: Planned
**Effort**: 2 days

```
tests/stress_test.c:
  - Concurrency: 100 clients × 1 server
  - Throughput: 1 Gbps sustained for 1 hour
  - Duration: 7-day continuous tunnel_run()
  - Chaos: network disconnect/reconnect, half-open connections,
           malformed frame injection
```

### 5.3 Fuzz Testing

**Status**: Planned
**Effort**: 2 days

```
$ make fuzz   # builds with -fsanitize=fuzzer

Targets:
  - frame_reader_try_next(): TCP stream frame parser
  - frame_parse(): frame decryption + authentication
  - socks5_accept(): SOCKS5 protocol handshake
  - iniconf_load(): INI config file parser
```

### 5.4 Unit Tests (iniconfig + keyfile)

**Status**: Planned
**Effort**: 1 day

- `tests/test_iniconfig.c`: section parsing, duplicate keys, edge cases
- `tests/test_keyfile.c`: hex parse, binary format, permission checks
- CI integration via `make test`

---

## Long-Term: Cookie-Based Anti-DoS

**Status**: Deferred (rate limiter is sufficient for most deployments)

### Design

When the server is under CPU pressure (ECDH saturation), it can
respond with a plaintext COOKIE frame instead of performing the
expensive ECDH calculation.

```
Client                              Server
  |                                    |
  |── HANDSHAKE_INIT ────────────────▶|  (40 bytes, encrypted)
  |     (eph_pub_c, ts_c)              |
  |                                    |── [if overloaded] ──
  |◀── COOKIE_REPLY ─────────────────|  (plaintext, no ECDH)
  |     cookie = MAC(sk, eph_c, ip)    |
  |                                    |
  |── HANDSHAKE_INIT + cookie ───────▶|  (56 bytes, encrypted)
  |     (eph_pub_c, ts_c, cookie)      |
  |                                    |  Validate cookie → ECDH
  |◀── HANDSHAKE_RESP ───────────────|  (normal flow)
```

```
New frame types: FRAME_COOKIE_REQUEST (0x07), FRAME_COOKIE_REPLY (0x08)
Cookie formula: SHA256(server_static_sk || eph_pub_c[0:16] || peer_ip || timestamp)[0:16]
Cookie lifetime: 120 seconds
Payload format with cookie: [eph_pub(32)][ts(8)][cookie(16)] = 56 bytes
```

### Trigger Logic

```
if (active_handshakes_in_progress > CPU_CORES * 2) {
    send_cookie_reply();   // defer ECDH
} else {
    do_ecdH_handshake();   // normal flow
}
```

---

## Priority Summary

| Phase | Item | Priority | Effort | Status |
|-------|------|----------|--------|--------|
| 1.1 | Per-IP rate limiting | 🔴 Critical | 2h | ✅ Done |
| 1.2 | Periodic re-key (120s) | 🔴 Critical | 1h | ✅ Done |
| 1.3 | Replay hardening | 🔴 Critical | 1h | ✅ Done |
| 2.3 | Config validation | 🟡 High | 1d | 📋 Planned |
| 3.1 | TCP multipath | 🟡 High | 3d | 📋 Planned |
| 2.1 | Daemon + pidfile | 🟡 High | 2d | 📋 Planned |
| 2.2 | Logging upgrade | 🟡 Medium | 1d | 📋 Planned |
| 5.2 | Stress tests | 🟡 Medium | 2d | 📋 Planned |
| 5.3 | Fuzz tests | 🟡 Medium | 2d | 📋 Planned |
| 5.4 | Unit tests | 🟡 Medium | 1d | 📋 Planned |
| 4.1 | macOS port | 🟢 Low | 3d | 📋 Planned |
| 4.2 | Embedded mode | 🟢 Low | 2d | 📋 Planned |
| 3.2 | UDP transport | 🟢 Low | 1w | 📋 Planned |
| 5.1 | Formal verification | 🟢 Low | 1w | 📋 Planned |
| — | Cookie anti-DoS | 🟢 Later | 3d | 📝 Deferred |
