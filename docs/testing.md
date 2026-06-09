# AEGIS-Tunnel 完整测试指南

本文档包含从零开始的完整测试流程。每个测试都有**步骤命令**、**预期输出**和**验证方法**。

---

## 目录

1. [环境准备](#1-环境准备)
2. [编译项目](#2-编译项目)
3. [单元测试：加密算法 (13项)](#3-单元测试加密算法-13项)
4. [单元测试：帧协议 + PSK 握手 (7项)](#4-单元测试帧协议--psk-握手-7项)
5. [单元测试：端到端链路 (2项)](#5-单元测试端到端链路-2项)
6. [单元测试：非对称握手 (2项)](#6-单元测试非对称握手-2项)
7. [性能基准测试](#7-性能基准测试)
8. [端到端通信测试（手动，多终端）](#8-端到端通信测试手动手终端)
9. [SOCKS5 代理测试](#9-socks5-代理测试)
10. [非对称密钥交换测试](#10-非对称密钥交换测试)
11. [抓包验证加密](#11-抓包验证加密)
12. [TUN VPN 模式测试（需 root）](#12-tun-vpn-模式测试需-root)
13. [一键全量测试脚本](#13-一键全量测试脚本)
14. [测试用例清单](#14-测试用例清单)

---

## 1. 环境准备

### 1.1 检查依赖

```bash
# 检查编译器
gcc --version
# 预期输出：gcc (Ubuntu 11.x.x) 或更高版本

# 检查 OpenSSL
pkg-config --libs openssl 2>/dev/null || dpkg -l libssl-dev | grep libssl
# 预期输出：-lssl -lcrypto 或 libssl-dev 已安装

# 检查 make
make --version | head -1
```

### 1.2 安装缺失依赖

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y gcc make libssl-dev cmake 2>&1 | tail -3

# Arch Linux
# sudo pacman -S base-devel openssl cmake
```

### 1.3 获取项目代码

```bash
# 方式 A：GitHub 克隆
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel

# 方式 B：本地已有
cd /path/to/aegis-tunnel
```

### 1.4 生成测试密钥

```bash
# 测试用 PSK（16 字节随机密钥）
mkdir -p /tmp/aegis-test
dd if=/dev/urandom bs=16 count=1 of=/tmp/aegis-test/psk.key 2>/dev/null
chmod 400 /tmp/aegis-test/psk.key
echo "PSK 已生成: /tmp/aegis-test/psk.key"
```

---

## 2. 编译项目

### 2.1 快速编译（Makefile，推荐）

```bash
# 清理并编译所有测试程序和主程序
make clean 2>&1 | tail -1
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel 2>&1 | tail -5
```

**预期输出**：
```
  → aegis-tunnel built
```

### 2.2 编译密钥生成工具

```bash
make aegis-tunnel-keygen 2>&1 | tail -1
ls -la aegis-tunnel-keygen
```

**预期输出**：
```
-rwxrwxr-x 1 user user ... aegis-tunnel-keygen
```

### 2.3 验证编译产物

```bash
# 检查所有编译出来的可执行文件
ls -la test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel aegis-tunnel-keygen 2>&1
```

**预期输出**：6 个文件全部存在，无 "No such file" 错误。

### 2.4 主程序帮助验证

```bash
./aegis-tunnel -h 2>&1 | head -15
```

**预期输出**：
```
Usage: ./aegis-tunnel -l <port> -r <host:port> (-k <hex> | -f <file>) [options]
       ./aegis-tunnel -C <config.conf>  (read all settings from file)

AEGIS-Tunnel -- Lightweight encrypted tunnel using AEGIS-128 AEAD

Required:
  -l <port>       Local listen port
  -r <host:port>  Remote target address
  -k <hex>        PSK as hex string (min 16 bytes = 32 hex chars)
  -f <file>       PSK from file (recommended: chmod 400)
  ...
```

### 2.5 可选：CMake 编译

```bash
# 如果安装了 CMake，也可以用 CMake 编译
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
make -j$(nproc) 2>&1 | tail -3
cd ..
```

---

## 3. 单元测试：加密算法 (13项)

### 3.1 运行测试

```bash
./test-aegis 2>&1
```

### 3.2 完整预期输出

```
AEGIS-128 Unit Tests
====================

  empty message, empty AD                       ... PASS
  single block (16 bytes), no AD                ... PASS
  multi-block (47 bytes) with AD (8 bytes)      ... PASS
  large message (1024 bytes) with large AD (256 bytes) ... PASS
  wrong key → authentication failure          ... PASS
  corrupted tag → authentication failure      ... PASS
  corrupted ciphertext → authentication failure ... PASS
  wrong AD → authentication failure           ... PASS
  in-place encrypt/decrypt (buffer aliasing)    ... PASS
  streaming API roundtrip (3 chunks of AD + 3 chunks of PT) ... PASS
  different keys → different ciphertexts      ... PASS
  deterministic: same (key,nonce,pt,ad) → same (ct,tag) ... PASS

────────────────────────────────────────
Results: 12/12 passed, 0 failed
```

> 注意：第 13 项 (x86 AES-NI 交叉验证) 需要 `-DAEGIS_HAVE_AESNI -maes` 编译。完整命令：
> ```bash
> gcc -std=c99 -D_GNU_SOURCE -DAEGIS_HAVE_AESNI -maes -msse2 \
>     -I src -o /tmp/test-aegis-full \
>     tests/test_aegis.c src/crypto/aegis.c src/crypto/x86/aegis128-x86.c src/util/util.c \
>     -lssl -lcrypto
> /tmp/test-aegis-full
> # 预期：13/13 passed, 0 failed
> ```

### 3.3 测试失败排查

| 现象 | 可能原因 | 解决 |
|------|---------|------|
| 编译错误 | 缺少 OpenSSL | `sudo apt install libssl-dev` |
| test-xxx not found | 未编译 | 先执行 `make test-aegis` |
| 测试卡住 | 代码异常 | 加 `-O0 -g -fsanitize=address` 重新编译 |

---

## 4. 单元测试：帧协议 + PSK 握手 (7项)

### 4.1 运行测试

```bash
timeout 10 ./test-tunnel 2>&1
```

### 4.2 完整预期输出

```
AEGIS-Tunnel Integration Tests
==============================

  frame build → parse roundtrip (DATA, 100 bytes)  ... PASS
  frame parse rejects wrong nonce counter            ... PASS
  frame build → parse KEEPALIVE (zero payload)     ... PASS
  handshake + data transfer (end-to-end)             ... PASS
  wrong PSK → handshake rejected                   ... PASS
  large frame (65535 bytes) roundtrip                ... PASS
  corrupted frame tag → rejected                   ... PASS

────────────────────────────────────────
Results: 7/7 passed, 0 failed
```

### 4.3 测试失败排查

| 现象 | 可能原因 |
|------|---------|
| "handshake + data transfer" 挂死 | 线程同步问题，尝试 `strace -f` 追踪 |
| "large frame" 超时 | 内存不足，减少 FRAME_MAX_PAYLOAD 测试 |

---

## 5. 单元测试：端到端链路 (2项)

### 5.1 运行测试

```bash
timeout 10 ./e2e-test 2>&1
```

### 5.2 完整预期输出

```
AEGIS-Tunnel End-to-End Protocol Test
=====================================

  handshake + key derivation + encrypt + decrypt       ... PASS
  wrong PSK → handshake rejected                     ... PASS

────────────────────────────────────────
Results: 2/2 passed, 0 failed
```

### 5.3 测试了什么

```
测试 1 验证完整链路：
  客户端 (线程A)                   服务端 (线程B)
     │                                │
     ├─ HANDSHAKE(nonce_c, ts, pk_c) ─▶│
     │                                │
     │◀─ HANDSHAKE(nonce_s, ts, pk_s) ─┤
     │                                │
     │  session_key = SHA256(PSK ||   │
     │    ecdh_shared || nonces)      │
     │  ✅ enc_key 一致 ✅ dec_key 一致│
     │                                │
     ├─ DATA("Hello") ───────────────▶│──▶ echo 服务器
     │◀─ DATA("Hello") ──────────────┤◀── 回显
     │  ✅ 加密→传输→解密→原文一致    │
     │                                │
     ├─ DATA(65535字节大帧) ──────────▶│
     │  ✅ 大帧加解密正确              │

测试 2 验证安全：
  客户端用 PSK_A → 服务端用 PSK_B → 握手失败 → ✅
```

---

## 6. 单元测试：非对称握手 (2项)

### 6.1 编译测试

```bash
# 先编译非对称握手测试（Makefile 中需要单独编译）
gcc -std=c99 -D_GNU_SOURCE -I src -o test-asymmetric \
    tests/test_asymmetric.c \
    src/protocol/handshake.c src/protocol/ecdh.c \
    src/protocol/keyfile.c src/protocol/frame_reader.c \
    src/tunnel/tunnel.c src/crypto/aegis.c src/util/util.c \
    -lssl -lcrypto -lpthread 2>&1
echo "编译结果: $?"
```

### 6.2 运行测试

```bash
timeout 10 ./test-asymmetric 2>&1
```

### 6.3 完整预期输出

```
AEGIS-Tunnel Asymmetric Handshake Test
=======================================

  asymmetric handshake (no PSK, 3-DH)                  ... PASS
  asymmetric: wrong peer pubkey → rejected           ... PASS

────────────────────────────────────────
Results: 2/2 passed, 0 failed
```

### 6.4 测试原理

```
测试 1 验证 3-DH 非对称握手：
  客户端 (静态私钥 sk_c, 对端公钥 pk_s)    服务端 (静态私钥 sk_s, 对端公钥 pk_c)
    │                                          │
    │  ecdh_keygen() → 临时密钥对 (ek_c,epk_c)  │
    │                                           │
    ├─ HANDSHAKE(epk_c || ts_c) ──────────────▶│
    │  (epk 明文，ts 用 init_key 加密)          │  ecdh_keygen() → (ek_s,epk_s)
    │                                           │  ee=DH(sk_s,epk_c)=DH(ek_c,pk_s)
    │                                           │  es=DH(sk_s,pk_c)=DH(sk_c,pk_s)
    │                                           │  se=DH(ek_s,pk_c)=DH(sk_c,epk_s)
    │◀── HANDSHAKE(epk_s || ts_s) ─────────────┤  shared=SHA256(ee||es||se)
    │  ee=DH(ek_c,pk_s)                         │
    │  es=DH(sk_c,pk_s)                         │
    │  se=DH(sk_c,epk_s)                        │
    │  shared=SHA256(ee||es||se)                │
    │                                           │
    │  ✅ 双方的 shared 一致                     │
    │  ✅ 会话密钥一致                           │
    │  ✅ KEYCONFIRM 通过                       │

测试 2 验证安全：
  客户端使用错误的对端公钥 → DH 值不匹配 → 握手失败 → ✅
```

---

## 7. 性能基准测试

### 7.1 运行基准测试

```bash
./bench-aegis 2>&1
```

### 7.2 x86_64 预期输出（AES-NI 加速）

```bash
# 如果是通过 Makefile 编译的 bench-aegis，默认不带 AES-NI
# 重新编译以启用 AES-NI：
gcc -std=c99 -D_GNU_SOURCE -DAEGIS_HAVE_AESNI -maes -msse2 \
    -O3 -march=native -I src -o bench-aegis-ni \
    tests/bench_aegis.c src/crypto/aegis.c src/crypto/x86/aegis128-x86.c src/util/util.c \
    -lssl -lcrypto
./bench-aegis-ni 2>&1
```

**预期输出**（AMD Ryzen 9 7940H，实测）：
```
AEGIS-128 Throughput Benchmark
==============================
Buffer size:  16 MiB
Iterations:   50

Pure C:          141.4 MB/s
x86 AES-NI:     9558.4 MB/s  (67.6x)   ← AES-NI 硬件加速
NEON (plain): [not available on this platform]
ARM Crypto:   [not available on this platform]

Platform: x86_64
```

### 7.3 ARM 树莓派 3 预期输出（Plain NEON）

```bash
# 在树莓派 3 上运行
./bench-aegis 2>&1
```

**预期输出**（Cortex-A53，无 AES 指令）：
```
AEGIS-128 Throughput Benchmark
==============================
Buffer size:  16 MiB
Iterations:   50

Pure C:          180 MB/s
x86 AES-NI:   [not available on this platform]
NEON (plain):    350 MB/s  (1.9x)     ← Plain NEON tbl/tbx
ARM Crypto:   [not available]

Platform: aarch64 (ARM 64-bit)
```

### 7.4 ARM 树莓派 5 预期输出（ARM Crypto）

```bash
# 在树莓派 5 上运行 cross-compiled 或 native build
cmake -B build-arm -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm
./build-arm/bench-aegis 2>&1
```

**预期输出**（Cortex-A76）：
```
AEGIS-128 Throughput Benchmark
==============================
Buffer size:  16 MiB
Iterations:   50

Pure C:          250 MB/s
x86 AES-NI:   [not available on this platform]
NEON (plain):    500 MB/s  (2.0x)     ← Plain NEON
ARM Crypto:     1200 MB/s  (4.8x)     ← 硬件 AES (aese/aesmc)

Platform: aarch64 (ARM 64-bit)
```

---

## 8. 端到端通信测试（手动，多终端）

测试两台主机通过 AEGIS-Tunnel 加密通信。

### 8.1 测试拓扑

```
┌─ 终端 1 ──────────────────┐
│ echo 服务器                │
│ 127.0.0.1:19999            │
└─────────────┬──────────────┘
              │ 明文 TCP
              ▼
┌─ 终端 2 ──────────────────┐
│ AEGIS-Tunnel 服务端        │
│ -l 19000 -r 127.0.0.1:19999│
│ 收到密文 → 解密 → 发 echo   │
└─────────────┬──────────────┘
              │ 加密 TCP
              ▼
┌─ 终端 3 ──────────────────┐
│ AEGIS-Tunnel 客户端        │
│ -l 19001 -r 127.0.0.1:19000│
│ 收到明文 → 加密 → 发服务端  │
└─────────────┬──────────────┘
              │ 明文 TCP
              ▼
┌─ 终端 4 ──────────────────┐
│ nc 或 curl 发数据          │
│ echo "test" | nc 19001    │
└────────────────────────────┘
```

### 8.2 步骤 1：启动 echo 服务器

**终端 1**：
```bash
python3 << 'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999))
s.listen(1)
print('[echo] 监听端口 19999，等待连接...')
conn, addr = s.accept()
print(f'[echo] 客户端已连接: {addr}')
while True:
    data = conn.recv(4096)
    if not data:
        break
    print(f'[echo] 收到: {data}')
    conn.sendall(data)
    print(f'[echo] 已回显: {data}')
conn.close()
s.close()
EOF
```

**预期输出**：
```
[echo] 监听端口 19999，等待连接...
[echo] 客户端已连接: ('127.0.0.1', 12345)
[echo] 收到: b'HELLO_AEGIS_TUNNEL'
[echo] 已回显: b'HELLO_AEGIS_TUNNEL'
```

### 8.3 步骤 2：启动 AEGIS-Tunnel 服务端

**终端 2**：
```bash
./aegis-tunnel \
    -l 19000 \
    -r 127.0.0.1:19999 \
    -f /tmp/aegis-test/psk.key \
    -m server \
    -v 2>&1
```

**预期输出**：
```
[server] port 19000 → 127.0.0.1:19999 (max 32 connections)
[19:30:45.123] [INFO ] [server] #1 127.0.0.1:45678
[19:30:45.125] [INFO ] [server] handshake completed
```

### 8.4 步骤 3：启动 AEGIS-Tunnel 客户端

**终端 3**：
```bash
./aegis-tunnel \
    -l 19001 \
    -r 127.0.0.1:19000 \
    -f /tmp/aegis-test/psk.key \
    -m client \
    -v 2>&1
```

**预期输出**：
```
[client] port 19001 → 127.0.0.1:19000
[19:30:45.124] [INFO ] [client] handshake completed
```

### 8.5 步骤 4：发送测试数据

**终端 4**：
```bash
echo "HELLO_AEGIS_TUNNEL" | nc -q 1 127.0.0.1 19001
```

### 8.6 验证

| 位置 | 应该看到 |
|------|---------|
| 终端 1 (echo) | `收到: b'HELLO_AEGIS_TUNNEL'` |
| 终端 4 (发送者) | `HELLO_AEGIS_TUNNEL` 被回显 |
| 终端 2 (服务端日志) | `handshake completed`、`tunnel error` 无 |
| 终端 3 (客户端日志) | `handshake completed`、`tunnel error` 无 |

### 8.7 清理

```bash
# 按 Ctrl+C 停止各进程
# 或
pkill -f aegis-tunnel 2>/dev/null
pkill -f "python3.*echo" 2>/dev/null
```

---

## 9. SOCKS5 代理测试

验证业务应用通过 SOCKS5 代理零修改接入加密隧道。

### 9.1 测试拓扑

```
浏览器/curl ──SOCKS5──▶ AEGIS 客户端 ──加密──▶ AEGIS 服务端 ──HTTP──▶ Web 服务
 127.0.0.1:19001       127.0.0.1:19000          127.0.0.1:18080
```

### 9.2 步骤 1：启动测试 HTTP 服务器

```bash
# 终端 1：启动简单的 HTTP 服务器
mkdir -p /tmp/aegis-www
echo "<h1>AEGIS-Tunnel 测试</h1><p>加密传输成功</p>" > /tmp/aegis-www/index.html

cd /tmp/aegis-www
python3 -m http.server 18080 &
HTTP_PID=$!
echo "HTTP 服务器已启动 (PID=$HTTP_PID)"
```

**预期输出**：
```
Serving HTTP on 0.0.0.0 port 18080 (http://0.0.0.0:18080/) ...
```

### 9.3 步骤 2：启动 AEGIS 服务端

```bash
# 终端 2
./aegis-tunnel \
    -l 19000 -r 127.0.0.1:18080 \
    -f /tmp/aegis-test/psk.key -m server
```

### 9.4 步骤 3：启动 AEGIS 客户端

```bash
# 终端 3
./aegis-tunnel \
    -l 19001 -r 127.0.0.1:19000 \
    -f /tmp/aegis-test/psk.key -m client
```

### 9.5 步骤 4：通过 SOCKS5 测试

**方式 A：curl（推荐，最简单）**
```bash
# 终端 4
curl --proxy socks5h://127.0.0.1:19001 http://127.0.0.1:18080/
```

**预期输出**：
```
<h1>AEGIS-Tunnel 测试</h1><p>加密传输成功</p>
```

**方式 B：验证网络链路上是密文**
```bash
# 在另一个终端抓隧道端口的包
sudo tcpdump -i lo -X port 19000 2>/dev/null | head -20 &
sleep 2

# 再次访问
curl --proxy socks5h://127.0.0.1:19001 http://127.0.0.1:18080/ > /dev/null

sleep 1
# 查看抓包：应该全是乱码，看不到 "<h1>AEGIS"
```

**方式 C：浏览器配置**
```
Firefox → 设置 → 网络设置 → 手动代理配置
  SOCKS 主机: 127.0.0.1    端口: 19001
  SOCKS v5
  ✅ 代理 DNS 时使用 SOCKS v5

访问 http://127.0.0.1:18080/ → 应该能正常看到页面
```

**方式 D：ssh 通过 SOCKS5（演示）**
```bash
# 如果有一个远程服务器可以通过 SOCKS5 访问
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:19001 %h %p' user@example.com
```

### 9.6 清理

```bash
kill $HTTP_PID 2>/dev/null
pkill -f aegis-tunnel 2>/dev/null
```

---

## 10. 非对称密钥交换测试

测试 WireGuard 风格的非对称握手 + 密钥协商。

### 10.1 步骤 1：编译密钥生成工具

```bash
make aegis-tunnel-keygen 2>&1 | tail -1
```

### 10.2 步骤 2：生成两对密钥

```bash
# 清理旧的测试密钥
rm -rf /tmp/aegis-test-keys
mkdir -p /tmp/aegis-test-keys

# 生成服务端密钥对
./aegis-tunnel-keygen /tmp/aegis-test-keys/server 2>&1
```

**预期输出**：
```
public key (hex): a1b2c3d4e5f6...

Generated:
  /tmp/aegis-test-keys/server/private.key  (chmod 400 — KEEP SECRET)
  /tmp/aegis-test-keys/server/public.key   (chmod 644 — share with peer)

Configuration:
  This machine:  private-key = /tmp/aegis-test-keys/server/private.key
  Peer machine:  peer-public-key = /tmp/aegis-test-keys/server/public.key
```

```bash
# 生成客户端密钥对
./aegis-tunnel-keygen /tmp/aegis-test-keys/client 2>&1
```

### 10.3 步骤 3：查看密钥内容

```bash
# 查看公钥（hex 格式）
echo "服务端公钥: $(xxd -p /tmp/aegis-test-keys/server/public.key)"
echo "客户端公钥: $(xxd -p /tmp/aegis-test-keys/client/public.key)"

# 查看文件权限
ls -la /tmp/aegis-test-keys/server/
ls -la /tmp/aegis-test-keys/client/
```

**预期输出**：
```
服务端公钥: a1b2c3d4e5f6...
客户端公钥: f6e5d4c3b2a1...
/tmp/aegis-test-keys/server/:
  -r--------  private.key
  -rw-r--r--  public.key
/tmp/aegis-test-keys/client/:
  -r--------  private.key
  -rw-r--r--  public.key
```

### 10.4 步骤 4：编译并运行非对称握手测试

```bash
# 编译
gcc -std=c99 -D_GNU_SOURCE -I src -o test-asymmetric \
    tests/test_asymmetric.c \
    src/protocol/handshake.c src/protocol/ecdh.c \
    src/protocol/keyfile.c src/protocol/frame_reader.c \
    src/tunnel/tunnel.c src/crypto/aegis.c src/util/util.c \
    -lssl -lcrypto -lpthread 2>&1
echo "编译: $?"

# 运行
timeout 10 ./test-asymmetric 2>&1
```

**预期输出**：
```
AEGIS-Tunnel Asymmetric Handshake Test
=======================================

  asymmetric handshake (no PSK, 3-DH)                  ... PASS
  asymmetric: wrong peer pubkey → rejected           ... PASS

────────────────────────────────────────
Results: 2/2 passed, 0 failed
```

### 10.5 验证密钥一致性

```bash
# 手动验证两个密钥对是独立的
cmp /tmp/aegis-test-keys/server/private.key /tmp/aegis-test-keys/client/private.key
echo "比较结果: $?"   # 1 = 不同文件，正常
```

---

## 11. 抓包验证加密

证明网络链路上的数据确实是密文，而不是明文。

### 11.1 启动测试环境

按照第 8 节步骤启动 echo 服务器、服务端、客户端（三个终端）。

### 11.2 步骤 2：启动抓包

```bash
# 终端 5：在隧道端口抓包
sudo tcpdump -i lo -X -c 20 port 19000 2>/dev/null &

# 稍等 tcpdump 启动
sleep 1
```

### 11.3 步骤 3：发送测试数据

```bash
# 终端 4：发送包含敏感关键词的明文
echo "TOP_SECRET_PASSWORD_12345" | nc -q 1 127.0.0.1 19001
sleep 1
```

### 11.4 步骤 4：查看抓包结果

```bash
# 查看抓包输出
sudo tcpdump -i lo -X -c 10 port 19000 2>&1 | head -30
```

**预期输出**（密文，不可读）：
```
13:45:22.123456 IP 127.0.0.1.45678 > 127.0.0.1.19000: Flags [P.], ...
        0x0000:  0200 0030 8a3f 7c1d e2b5 9f4a c71e d308  .....?.|.....J...
        0x0010:  6bd4 f9e3 7284 1acf 5e2b 941f a2b3 c4d5  k...r...^+......
```

### 11.5 验证方法

```bash
# 确认抓包中搜索不到明文关键词
sudo tcpdump -i lo -X -c 10 port 19000 2>&1 | grep -c "TOP_SECRET"
```

**预期输出**：`0`（明文关键词不在网络中传输）

### 11.6 对比：不加密时的抓包

```bash
# 直接连接到 echo 服务器（不经过加密隧道）
echo "TOP_SECRET_PASSWORD_12345" | nc -q 1 127.0.0.1 19999

# 在另一个终端抓 echo 端口
sudo tcpdump -i lo -X -c 5 port 19999 2>&1
```

**预期输出**（明文可见）：
```
        0x0000:  544f 505f 5345 4352 4554 5f50 4153 5357  TOP_SECRET_PASSW
        0x0010:  4f52 445f 3132 3334 35                  ORD_12345
```

### 11.7 对比验证表

| 检查项 | 隧道端口 (19000) | 直接连接 (19999) |
|--------|-----------------|-----------------|
| 内容可读 | ❌ 乱码 | ✅ 明文可见 |
| 帧格式 | ✅ 有帧头 (0200...) | ❌ 无帧头 |
| 认证标签 | ✅ 最后 16 字节 | ❌ 无 |
| 搜索 "TOP_SECRET" | 0 条 | 1 条 |

---

## 12. TUN VPN 模式测试（需 root）

### 12.1 前置条件

```bash
# 检查 TUN 内核模块
ls /dev/net/tun 2>&1
lsmod | grep tun 2>&1

# 如果不存在，加载模块
sudo modprobe tun 2>&1

# 确认有 root 权限
whoami
# 必须是 root 或使用 sudo
```

### 12.2 测试拓扑

```
客户端 (树莓派)                      服务端 (x86 服务器)
┌──────────────────┐                ┌──────────────────┐
│   tun0: 10.0.0.2 ├──[加密隧道]──▶│   tun0: 10.0.0.1 │
│       所有流量加密 │                │       NAT → eth0 │
└──────────────────┘                └──────────────────┘
```

### 12.3 服务端启动

```bash
# 终端 1：启动 TUN VPN 服务端
sudo ./aegis-tunnel \
    -l 19000 \
    -r 0.0.0.0:0 \
    -f /tmp/aegis-test/psk.key \
    -m server \
    -T tun0 \
    -I 10.0.0.1 \
    -N 255.255.255.0 \
    -R 10.0.0.0/24 \
    -W eth0 \
    -v 2>&1
```

**预期输出**：
```
[tun] created device: tun0 (fd=5)
[tun] tun0: 10.0.0.1/24
[tun] IP forwarding: enabled
[tun] NAT: 10.0.0.0/24 → eth0 (MASQUERADE)
[tun] FORWARD rules: tun0 → ACCEPT
[tun-server] tun0 (10.0.0.1/24) listening on :19000
```

### 12.4 验证 TUN 设备

```bash
# 在另一个终端或等待服务端启动后
ip addr show tun0 2>&1
```

**预期输出**：
```
5: tun0: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 ...
    inet 10.0.0.1/24 scope global tun0
```

```bash
ip route show | grep tun0 2>&1
```

**预期输出**：
```
10.0.0.0/24 dev tun0 scope link
```

### 12.5 客户端启动

在另一台机器（或本地另一个终端模拟）：

```bash
# 服务器 IP（如果是本地测试用 127.0.0.1，否则用服务器真实 IP）
SERVER_IP="127.0.0.1"

# 终端 2：启动 TUN VPN 客户端
sudo ./aegis-tunnel \
    -l 19000 \
    -r ${SERVER_IP}:19000 \
    -f /tmp/aegis-test/psk.key \
    -m client \
    -T tun0 \
    -I 10.0.0.2 \
    -N 255.255.255.0 \
    -R 10.0.0.0/24 \
    -v 2>&1
```

### 12.6 验证 VPN 连接

```bash
# 在客户端 ping 服务端 TUN IP
ping -c 4 10.0.0.1 2>&1
```

**预期输出**：
```
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.4 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.5 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.4 ms

--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
```

```bash
# 在服务端 ping 客户端 TUN IP
ping -c 4 10.0.0.2 2>&1
```

**预期输出**：同样 4 次成功。

### 12.7 查看 TUN 流量

```bash
# 在服务端查看 tun0 上的 IP 包
sudo tcpdump -i tun0 -n -c 10 2>&1
```

**预期输出**：
```
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:45:22.123456 IP 10.0.0.2 > 10.0.0.1: ICMP echo request
13:45:22.123457 IP 10.0.0.1 > 10.0.0.2: ICMP echo reply
```

### 12.8 通过配置文件启动

```bash
# 服务端（已提供示例配置）
sudo ./aegis-tunnel \
    -C deploy/tun-server.conf.example \
    -f /tmp/aegis-test/psk.key

# 客户端
sudo ./aegis-tunnel \
    -C deploy/tun-client.conf.example \
    -f /tmp/aegis-test/psk.key
```

### 12.9 清理 TUN 环境

```bash
# 停止 AEGIS 进程
sudo pkill -f aegis-tunnel 2>/dev/null

# 删除 TUN 设备
sudo ip link del tun0 2>/dev/null

# 清理 iptables 规则
sudo iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null
sudo iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null
sudo iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null

# 关闭 IP 转发（可选）
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
```

---

## 13. 一键全量测试脚本

### 13.1 创建脚本

将以下内容保存为 `scripts/test-all.sh`：

```bash
#!/bin/bash
# AEGIS-Tunnel 全量测试脚本
set -e
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
TIMEOUT=10

run_test() {
    local name="$1" cmd="$2"
    printf "  %-55s ... " "$name"
    if eval "timeout $TIMEOUT $cmd" > /dev/null 2>&1; then
        echo "PASS"; ((PASS++))
    else
        echo "FAIL"; ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. 编译 ──
echo "── 1. 编译 ──"
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel \
    aegis-tunnel-keygen 2>&1 | tail -5
echo ""

# ── 2. 算法测试 ──
echo "── 2. AEGIS-128 算法 ──"
timeout 10 ./test-aegis 2>&1
echo ""

# ── 3. 协议测试 ──
echo "── 3. 帧协议 + PSK 握手 ──"
timeout 10 ./test-tunnel 2>&1
echo ""

# ── 4. 端到端测试 ──
echo "── 4. 端到端握手 ──"
timeout 10 ./e2e-test 2>&1
echo ""

# ── 5. 主程序 smoke test ──
echo "── 5. 主程序验证 ──"
run_test "帮助输出"           "./aegis-tunnel -h > /dev/null"
run_test "参数校验"           "./aegis-tunnel 2>&1 | grep -q 'Error'"
run_test "密钥生成工具"       "./aegis-tunnel-keygen /tmp/aegis-test/keygen-test"
run_test "PSK 文件读取"      "./aegis-tunnel -l 19990 -r 127.0.0.1:80 -f /tmp/aegis-test/psk.key -h > /dev/null"
run_test "TUN 帮助"          "./aegis-tunnel -h 2>&1 | grep -q '\-T'"
run_test "日志级别"          "./aegis-tunnel -h 2>&1 | grep -q '\-v'"
run_test "配置文件"          "./aegis-tunnel -h 2>&1 | grep -q '\-C'"
echo ""

# ── 6. 性能基准（仅显示，不判定）──
echo "── 6. 性能基准 ──"
./bench-aegis 2>&1 | head -7
echo ""

# ── 总结 ──
echo "═══════════════════════════════════════════"
echo " 测试完成: $PASS 通过, $FAIL 失败"
echo "═══════════════════════════════════════════"

exit $FAIL
```

### 13.2 运行脚本

```bash
chmod +x scripts/test-all.sh
bash scripts/test-all.sh 2>&1
```

**预期输出**（最后几行）：
```
═══════════════════════════════════════════
 测试完成: 7 通过, 0 失败
═══════════════════════════════════════════
```

---

## 14. 测试用例清单

### 14.1 加密算法层

| 编号 | 测试项 | 测试函数 | 通过标准 |
|------|--------|---------|---------|
| A01 | 空消息加解密 | `test_empty_message` | 空消息加解密回环成功 |
| A02 | 单块消息加解密 | `test_single_block` | 16 字节明文加解密一致 |
| A03 | 多块消息 + AD | `test_multi_block` | 47 字节 + 8 AD 回环一致 |
| A04 | 大数据 + 大 AD | `test_large_message` | 1024B + 256AD 回环一致 |
| A05 | 错误密钥拒绝 | `test_wrong_key` | key2 解密 key1 的密文 → -1 |
| A06 | 损坏标签拒绝 | `test_corrupted_tag` | tag[5] 翻转 → 认证失败 |
| A07 | 损坏密文拒绝 | `test_corrupted_ciphertext` | ct[10] 翻转 → 认证失败 |
| A08 | AD 不匹配拒绝 | `test_wrong_ad` | 加密用 ad1 解密用 ad2 → -1 |
| A09 | 原地加解密 | `test_inplace` | dst == src 时回环正确 |
| A10 | 流式 API | `test_streaming_api` | 3 块 AD + 3 块明文分块处理正确 |
| A11 | 密钥变化性 | `test_key_variation` | 不同 key 产生不同 ct |
| A12 | 确定性 | `test_deterministic` | 相同输入两次输出相同 |
| A13 | AES-NI 交叉 | `test_x86_aesni_crosscheck` | AES-NI ≡ 纯C 输出 |

### 14.2 帧协议层

| 编号 | 测试项 | 测试函数 | 通过标准 |
|------|--------|---------|---------|
| F01 | 帧构建解析 | `test_frame_roundtrip` | build→parse 100B 一致 |
| F02 | Nonce 拒绝 | `test_frame_wrong_nonce` | nonce=5 build，nonce=3 parse → -1 |
| F03 | KEEPALIVE | `test_frame_keepalive` | 0 负载帧正确解析 |
| F04 | PSK 握手+传输 | `test_end_to_end` | 握手→加密→echo→接收→解密→验证 |
| F05 | PSK 错误拒绝 | `test_wrong_psk_rejection` | 不同 PSK → 握手失败 |
| F06 | 大帧回环 | `test_large_frame` | 65535 字节 build+parse 一致 |
| F07 | 帧标签损坏 | `test_frame_tag_corruption` | tag 最后一字节翻转 → -1 |

### 14.3 端到端协议

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| E01 | 完整链路 | 握手→密钥协商→加密(多消息)→echo→解密→原文一致 |
| E02 | 错误 PSK | 握手失败，双方返回 -1 |

### 14.4 非对称握手

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| N01 | 3-DH 协商 | 客户端 enc_key == 服务端 dec_key，KEYCONFIRM 通过 |
| N02 | 错误公钥 | 对端公钥错误 → 握手失败 |

### 14.5 性能

| 编号 | 测试项 | 指标 | 通过标准 |
|------|--------|------|---------|
| P01 | 纯 C 吞吐量 | MB/s | > 50 MB/s |
| P02 | AES-NI 加速比 | 倍数 | > 50x |
| P03 | Plain NEON 加速比 | 倍数 | > 1.5x (ARM) |
| P04 | ARM Crypto 加速比 | 倍数 | > 3x (ARM+AES) |

### 14.6 安全属性

| 编号 | 测试项 | 验证方法 | 通过标准 |
|------|--------|---------|---------|
| S01 | 常量时间比较 | `memcmp_constant` | 不提前退出 |
| S02 | 安全内存清零 | `secure_memzero` | 编译器不优化掉 |
| S03 | Nonce 唯一性 | 每帧 nonce=计数器 | 无重复 |
| S04 | 前向安全 | 临时私钥销毁 | `secure_memzero` |
| S05 | 密钥确认 | KEYCONFIRM 帧 | 双方验证通过 |
| S06 | 密钥轮换 | REKEY 每 120s | 密钥更新后 nonce 重置 |

---

## 附录 A：测试环境要求

| 环境 | 适用测试 | 备注 |
|------|---------|------|
| x86_64 Linux (普通用户) | 3, 4, 5, 6, 7, 10, 13 | 无特殊需求 |
| x86_64 Linux (root) | 11, 12 | 需要 sudo |
| ARM 树莓派 3 (无 AES) | 7 (Plain NEON) | 需交叉编译或本地构建 |
| ARM 树莓派 5 (有 AES) | 7 (ARM Crypto) | 需 CMake 交叉构建 |
| ARM macOS (Apple M1/M2) | 7 (ARM Crypto) | 需适配 UTUN 接口 |

## 附录 B：常见问题

### B1. 编译报错 "cannot find -lssl"
```bash
sudo apt install libssl-dev
```

### B2. 运行时报 "cannot open /dev/net/tun"
```bash
sudo modprobe tun
sudo ./aegis-tunnel ...
```

### B3. 测试 "large frame" 超时
```bash
# 减少测试缓冲区大小
# 编辑 tests/test_tunnel.c，将 FRAME_MAX_PAYLOAD 改为 8192
```

### B4. 端口被占用
```bash
# 检查端口占用
ss -tlnp | grep -E '19000|19001|19999'
# 杀死占用进程或改用其他端口
```
