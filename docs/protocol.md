# AEGIS-Tunnel 协议规范 v0.1.0

## 1. 概述

AEGIS-Tunnel 协议在 TCP 之上提供加密隧道功能。协议使用 AEGIS-128 认证加密算法保护数据传输，并通过 X25519 椭圆曲线 Diffie-Hellman（3-DH）非对称握手进行双向认证和会话密钥协商。

## 2. 加密算法

### 2.1 AEGIS-128

| 参数 | 值 |
|------|-----|
| 密钥长度 | 16 字节（128 位） |
| Nonce 长度 | 16 字节（128 位） |
| 认证标签长度 | 16 字节（128 位） |
| 明文块大小 | 16 字节 |
| 关联数据 (AD) | 帧头 4 字节 |

AEGIS-128 是 CAESAR 竞赛的冠军算法，正在被 IETF CFRG 标准化。

### 2.2 Nonce 构造

```
nonce[16] = little_endian_64(counter) || 0x00 * 8
```

每个方向维护独立的 64 位单调计数器：
- 握手帧使用 nonce 计数器值 0
- 数据帧从 nonce 计数器值 1 开始递增

## 3. 帧协议

### 3.1 线格式

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

### 3.2 字段说明

- **Type** (1 字节): 帧类型
  - `0x01` — HANDSHAKE
  - `0x02` — DATA
  - `0x03` — KEEPALIVE
  - `0x04` — CLOSE

- **Flags** (1 字节): 标志位
  - `0x00` — 无标志
  - `0x01` — 发起方方向标记

- **Length** (2 字节, 大端序): 负载长度 (0..65535)

- **Payload** (变长): AEGIS-128 加密的负载

- **Tag** (16 字节): AEGIS-128 认证标签

### 3.3 AEGIS 参数

```
encrypt(payload, ad=frame_header[0..3], nonce=nonce_from_counter, key=session_key)
```

帧头（4 字节）作为关联数据传递给 AEGIS-128。

## 4. 握手协议（X25519 3-DH）

### 4.1 加密后端

握手帧使用 AEGIS-128 加密，自动选择最优后端（x86 AES-NI > ARM Crypto > ARM NEON > Pure C）。

### 4.2 握手帧负载格式

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

- handshake_init: 32 字节临时公钥 + 8 字节时间戳（共 40 字节明文）
- handshake_resp: 同格式
- 加密后帧 = 4 字节头 + 40 字节密文 + 16 字节 tag = 60 字节线数据

### 4.3 握手流程

```
客户端                                         服务器
  |                                               |
  | 生成临时密钥对 (eph_sk_c, eph_pk_c)            |
  |                                               |
  |── HANDSHAKE(eph_pk_c || ts_c) ──────────────▶|
  |   (用 init_key 加密, nonce=0)                 | 尝试所有已知 Peer 公钥
  |                                               | 验证时间戳 ±60s
  |                                               | 生成临时密钥对 (eph_sk_s, eph_pk_s)
  |                                               |
  |◀── HANDSHAKE(eph_pk_s || ts_s) ──────────────│
  |   (用 resp_key 加密, nonce=0)                 |
  |                                               |
  |  双方计算共享密钥:                             |
  |  ee = X25519(eph_sk, peer_eph_pk)             |
  |  es = X25519(static_sk, peer_eph_pk)          |
  |  se = X25519(eph_sk, peer_static_pk)          |
  |  shared = SHA256(ee || es || se || "shared")  |
  |                                               |
  |◀══ KEY_CONFIRM ─══════════════════════════════│ (空帧，AEGIS 加密)
  |══▶ KEY_CONFIRM ─══════════════════════════════▶| (空帧，AEGIS 加密)
  |                                               |
  |══▶ DATA (加密流量, nonce=1,2,3...) ──────────▶|
  |◀══ DATA (加密流量, nonce=1,2,3...) ───────────│
```

### 4.4 密钥派生

握手初始密钥（客户端发起）：
```
ee_init = X25519(client_static_sk, server_static_pk)
es_init = X25519(client_eph_sk, server_static_pk)
init_key = SHA256(ee_init || es_init || "init")[0..15]
```

握手响应密钥（服务端回复）：
```
resp_key = SHA256(shared_secret || "resp")[0..15]
```

会话密钥（保护数据）：
```
shared_secret = SHA256(ee || es || se || "shared")
session_enc_key = shared_secret[0..15]
session_dec_key = shared_secret[16..31]
```

客户端使用 enc_key 加密发送方向，dec_key 解密接收方向；
服务器端则相反（enc_key 和 dec_key 互换）。

### 4.5 KEY_CONFIRM

握手完成后，服务端和客户端各发送一个空的 KEY_CONFIRM 帧（payload=0），用协商后的会话密钥加密。双方验证解密成功后才进入数据传输阶段，防止中间人篡改握手。

## 5. 安全考虑

### 5.1 认证

- 标签验证使用常量时间比较（逐字节 XOR 累积），防止时序侧信道
- 认证失败时不返回任何错误信息（防止 Oracle 攻击）

### 5.2 防重放

- 握手阶段：时间戳在 ±60 秒窗口内
- 数据传输阶段：每方向独立的 monotonic nonce 计数器

### 5.3 Nonce 重用

每个 (key, nonce) 对严格保证单一使用。Nonce 计数器溢出（> 2^64 帧）
被视为致命错误，连接必须终止。

### 5.4 内存安全

- 密钥、nonce、明文缓冲区使用后通过 `secure_memzero()` 清零
- 使用 volatile 指针防止编译器优化移除清零操作

### 5.5 限制

- 提供前向安全性（每次会话独立生成临时密钥对）
- 不提供身份保护（握手帧使用 ECDH 派生密钥加密，帧头明文）
- 最大帧负载 65535 字节
- 不支持分片或流控制
- Re-key 默认禁用（需显式配置 PSK 和 rekey_sec）
