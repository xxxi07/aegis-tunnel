# AEGIS-Tunnel Protocol Specification v0.2.0

## 1. Overview

The AEGIS-Tunnel protocol provides encrypted tunneling over TCP. It uses AEGIS-128 authenticated encryption to protect data in transit and performs mutual authentication and session key negotiation via an X25519 elliptic-curve Diffie-Hellman (3-DH) asymmetric handshake.

## 2. Cryptographic Algorithms

### 2.1 AEGIS-128

| Parameter | Value |
|-----------|-------|
| Key length | 16 bytes (128 bits) |
| Nonce length | 16 bytes (128 bits) |
| Authentication tag length | 16 bytes (128 bits) |
| Plaintext block size | 16 bytes |
| Associated data (AD) | Frame header (4 bytes) |

AEGIS-128 is a CAESAR competition winner being standardized by the IETF CFRG.

### 2.2 Nonce Construction

```
nonce[16] = little_endian_64(counter) || 0x00 × 8
```

Each direction maintains an independent 64-bit monotonic counter:
- Handshake frames use nonce counter value 0
- Data frames start at nonce counter value 1 and increment

## 3. Frame Protocol

### 3.1 Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |         Length (BE)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Encrypted Payload (0..65535)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Authentication Tag (16 bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Descriptions

- **Type** (1 byte): Frame type
  - `0x01` — HANDSHAKE
  - `0x02` — DATA
  - `0x03` — KEEPALIVE
  - `0x04` — CLOSE

- **Flags** (1 byte): Flag bits
  - `0x00` — No flags
  - `0x01` — Initiator direction marker

- **Length** (2 bytes, big-endian): Payload length (0..65535)

- **Payload** (variable): AEGIS-128 encrypted payload

- **Tag** (16 bytes): AEGIS-128 authentication tag

### 3.3 AEGIS Parameters

```
encrypt(payload, ad=frame_header[0..3], nonce=nonce_from_counter, key=session_key)
```

The 4-byte frame header is passed as associated data to AEGIS-128.

## 4. Handshake Protocol (X25519 3-DH)

### 4.1 Crypto Backend

Handshake frames are encrypted with AEGIS-128, which automatically selects the optimal backend (x86 AES-NI > ARM Crypto > ARM NEON > Pure C).

### 4.2 Handshake Frame Payload Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|               Ephemeral Public Key (32 bytes)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Timestamp (8 bytes, BE)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- handshake_init: 32-byte ephemeral public key + 8-byte timestamp (40 bytes plaintext)
- handshake_resp: Same format
- Encrypted frame = 4-byte header + 40-byte ciphertext + 16-byte tag = 60 bytes on wire

### 4.3 Handshake Flow

```
Client                                        Server
  |                                               |
  | Generate ephemeral keypair (eph_sk_c, eph_pk_c) |
  |                                               |
  |── HANDSHAKE(eph_pk_c || ts_c) ──────────────▶|
  |   (encrypted with init_key, nonce=0)          | Try all known peer public keys
  |                                               | Verify timestamp ±60s
  |                                               | Generate ephemeral keypair (eph_sk_s, eph_pk_s)
  |                                               |
  |◀── HANDSHAKE(eph_pk_s || ts_s) ──────────────│
  |   (encrypted with resp_key, nonce=0)          |
  |                                               |
  |  Both sides compute shared secret:            |
  |  ee = X25519(eph_sk, peer_eph_pk)             |
  |  es = X25519(static_sk, peer_eph_pk)          |
  |  se = X25519(eph_sk, peer_static_pk)          |
  |  shared = SHA256(ee || es || se || "shared")  |
  |                                               |
  |◀══ KEY_CONFIRM ─══════════════════════════════│ (empty frame, AEGIS-encrypted)
  |══▶ KEY_CONFIRM ─══════════════════════════════▶| (empty frame, AEGIS-encrypted)
  |                                               |
  |══▶ DATA (encrypted traffic, nonce=1,2,3...) ─▶|
  |◀══ DATA (encrypted traffic, nonce=1,2,3...) ──│
```

### 4.4 Key Derivation

Handshake init key (client initiates):
```
ee_init = X25519(client_static_sk, server_static_pk)
es_init = X25519(client_eph_sk, server_static_pk)
init_key = SHA256(ee_init || es_init || "init")[0..15]
```

Handshake response key (server replies):
```
resp_key = SHA256(shared_secret || "resp")[0..15]
```

Session keys (protect data):
```
shared_secret = SHA256(ee || es || se || "shared")
session_enc_key = shared_secret[0..15]
session_dec_key = shared_secret[16..31]
```

The client uses enc_key for the send direction and dec_key for the receive direction;
roles are reversed on the server (enc_key and dec_key swapped).

### 4.5 Key Confirmation

After the handshake completes, both server and client each send an empty KEY_CONFIRM frame (payload=0), encrypted with the negotiated session keys. Both sides verify successful decryption before entering the data transfer phase, preventing man-in-the-middle tampering with the handshake.

## 5. Security Considerations

### 5.1 Authentication

- Tag verification uses constant-time comparison (byte-wise XOR accumulation) to prevent timing side-channels
- No error details are returned on authentication failure (prevents oracle attacks)

### 5.2 Replay Protection

- Handshake phase: Timestamp within ±60-second window
- Data transfer phase: Independent monotonic nonce counters per direction

### 5.3 Nonce Reuse Prevention

Each (key, nonce) pair is strictly single-use. Nonce counter overflow (> 2^64 frames)
is handled by automatic session re-keying before the limit is reached.

### 5.4 Memory Safety

- Keys, nonces, and plaintext buffers are zeroed via `secure_memzero()` after use
- Volatile pointers prevent compiler optimization from eliding zeroing operations

### 5.5 Limitations

- Forward secrecy is provided (fresh ephemeral keypair generated per session)
- No identity protection (handshake frames are encrypted with ECDH-derived keys; frame headers are plaintext)
- Maximum frame payload: 65,535 bytes
- No fragmentation or flow control
- Re-key is auto-triggered on nonce pressure (session PSK is derived internally)
