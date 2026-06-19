# AEGIS-Tunnel 协议规范 v0.2.0

## 1. 概述

AEGIS-Tunnel 协议在 TCP 之上提供加密隧道功能。使用 AEGIS-128 认证加密算法保护数据传输，通过 X25519 椭圆曲线 Diffie-Hellman（3-DH）非对称握手进行双向认证和会话密钥协商。

## 2. 加密算法

### 2.1 AEGIS-128

| 参数 | 值 |
|------|-----|
| 密钥长度 | 16 字节（128 位） |
| Nonce 长度 | 16 字节（128 位） |
| 认证标签长度 | 16 字节（128 位） |
| 明文块大小 | 16 字节 |
| 关联数据 (AD) | 帧头 4 字节 |

AEGIS-128 是 CAESAR 竞赛冠军算法，已被 IETF CFRG 标准化。

### 2.2 Nonce 构造

```
nonce[16] = little_endian_64(counter) || 0x00 × 8
```

每个方向维护独立的 64 位单调计数器：
- 握手帧使用 nonce 计数器值 0
- 数据帧从 nonce 计数器值 1 开始递增

### 2.3 加密后端选择

运行时自动选择最优后端：
```
x86 AES-NI (~9500 MB/s) > ARM Crypto > ARM NEON > Pure C (~110 MB/s)
```
可通过环境变量 `AEGIS_PURE_C=1` 强制使用纯 C 后端。

## 3. 帧协议

### 3.1 线格式

```
 0      1      2-3         4...(N+3)      (N+4)...(N+19)
+------+------+--------+--------//----+--------//--------+
| type | flags| length |   payload     |    tag (16 B)    |
|  1   |  1   |  2 BE  |  0..65535 B   |                  |
+------+------+--------+--------//----+--------//--------+
```

### 3.2 字段说明

- **Type** (1 字节): 帧类型
  - `0x01` — HANDSHAKE（握手）
  - `0x02` — DATA（数据）
  - `0x03` — KEEPALIVE（心跳）
  - `0x04` — CLOSE（关闭）
  - `0x05` — KEY_CONFIRM（密钥确认）
  - `0x06` — REKEY（密钥轮换）

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

帧头 4 字节作为关联数据传递给 AEGIS-128。

## 4. 握手协议（X25519 3-DH）

### 4.1 握手帧负载格式

```
+-----------------------------------+
|     Ephemeral Public Key (32 B)   |
+-----------------------------------+
|       Timestamp (8 B, BE)         |
+-----------------------------------+
```

- handshake_init: 32 字节临时公钥 + 8 字节时间戳 = 40 字节明文
- handshake_resp: 同格式
- 加密后帧 = 4 字节头 + 40 字节密文 + 16 字节 tag = 60 字节线数据

### 4.2 握手流程

```
客户端                                       服务端
  |                                             |
  | 生成临时密钥对 (eph_sk_c, eph_pk_c)          |
  |                                             |
  |── HANDSHAKE(eph_pk_c || ts_c) ────────────▶|
  |   (init_key 加密, nonce=0)                  | 尝试所有已知 Peer 公钥
  |                                             | 验证时间戳 ±60s + 重放检测
  |                                             | 生成临时密钥对 (eph_sk_s, eph_pk_s)
  |                                             |
  |◀── HANDSHAKE(eph_pk_s || ts_s) ────────────│
  |   (resp_key 加密, nonce=0)                  |
  |                                             |
  |  双方计算共享密钥:                           |
  |  ee = X25519(eph_sk, peer_eph_pk)           |
  |  es = X25519(static_sk, peer_eph_pk)        |
  |  se = X25519(eph_sk, peer_static_pk)        |
  |  shared = SHA256(ee || es || se || "shared")|
  |                                             |
  |◀══ KEY_CONFIRM ═════════════════════════════│ (服务端先发，空帧 AEGIS 加密)
  |══▶ KEY_CONFIRM ═════════════════════════════▶│ (客户端验证)
  |                                             |
  |══▶ DATA (加密流量, nonce=1,2,3...) ────────▶|
  |◀══ DATA (加密流量, nonce=1,2,3...) ─────────│
```

### 4.3 密钥派生

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
shared_secret  = SHA256(ee || es || se || "shared")
enc_key        = shared_secret[0..15]
dec_key        = shared_secret[16..31]
```

客户端用 enc_key 加密发送方向，dec_key 解密接收方向；服务端相反。

### 4.4 KEY_CONFIRM

握手完成后双方各发一个空的 KEY_CONFIRM 帧（payload=0），用协商后的会话密钥加密。双方验证解密成功后才进入数据传输阶段，防止中间人篡改握手。

### 4.5 会话密钥轮换 (Re-Key)

默认每 120 秒自动触发一次 ECDH 密钥轮换：

```
发起方 → 对端: REKEY(eph_pub_new)
对端   → 发起方: REKEY(eph_pub_peer)
双方计算: new_key = SHA256(session_psk || ecdh_shared || nonce1 || nonce2)
nonce 归零，密钥原子替换
```

session_psk 由 `tunnel_init` 自动从会话密钥派生（enc_key ⊕ dec_key），无需外部配置。

## 5. 安全机制

### 5.1 认证

- 标签验证使用恒定时间比较（字节 XOR 累积），防止时序侧信道
- 认证失败时不返回任何错误详情（防止 Oracle 攻击）
- 握手重放: (时间戳, 临时公钥前缀) 滑动窗口检测，128 槽

### 5.2 防重放

- 握手阶段: 时间戳 ±60s 窗口 + 重放缓存去重
- 数据传输: 每方向独立 monotonic nonce 计数器
- 抗 DoS: per-IP 握手速率限制（5 次/60s/IP）

### 5.3 Nonce 重用预防

每个 (key, nonce) 对严格保证单次使用。Nonce 接近溢出时自动触发 re-key。

### 5.4 前向安全性

每次会话独立生成临时密钥对。即使静态私钥泄露，历史会话密钥不可恢复。

### 5.5 限制

- 最大帧负载 65,535 字节
- 无分片或流控制
- 仅支持 IPv4（IPv6 待实现）
