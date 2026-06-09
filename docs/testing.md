# AEGIS-Tunnel 完整测试指南

## 目录

1. [快速开始（一键测试）](#1-快速开始一键测试)
2. [单元测试：加密算法 (12项)](#2-单元测试加密算法-12项)
3. [单元测试：帧协议 + PSK 握手 (7项)](#3-单元测试帧协议--psk-握手-7项)
4. [单元测试：端到端链路 (2项)](#4-单元测试端到端链路-2项)
5. [单元测试：非对称握手 (2项)](#5-单元测试非对称握手-2项)
6. [性能基准测试](#6-性能基准测试)
7. [端到端通信测试（PSK 模式）](#7-端到端通信测试psk-模式)
8. [非对称握手测试](#8-非对称握手测试)
9. [TOFU 自动交换公钥测试](#9-tofu-自动交换公钥测试)
10. [SOCKS5 透明代理测试](#10-socks5-透明代理测试)
11. [TUN VPN 模式测试](#11-tun-vpn-模式测试)
12. [抓包验证加密](#12-抓包验证加密)
13. [问题排查](#13-问题排查)

---

## 1. 快速开始（一键测试）

```bash
cd aegis-tunnel
make clean && make        # 编译 7 个二进制文件
bash scripts/test-all.sh  # 运行全部自动化测试
```

**预期输出**：
```
═══════════════════════════════════════════
 测试完成: 7 通过, 0 失败
═══════════════════════════════════════════
```

---

## 2. 单元测试：加密算法 (12项)

```bash
./test-aegis
```

**完整预期输出**：
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

---

## 3. 单元测试：帧协议 + PSK 握手 (7项)

```bash
timeout 10 ./test-tunnel
```

**完整预期输出**：
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

---

## 4. 单元测试：端到端链路 (2项)

```bash
timeout 10 ./e2e-test
```

**完整预期输出**：
```
AEGIS-Tunnel End-to-End Protocol Test
=====================================

  handshake + key derivation + encrypt + decrypt       ... PASS
  wrong PSK → handshake rejected                     ... PASS

────────────────────────────────────────
Results: 2/2 passed, 0 failed
```

---

## 5. 单元测试：非对称握手 (2项)

```bash
timeout 10 ./test-asymmetric
```

**完整预期输出**：
```
AEGIS-Tunnel Asymmetric Handshake Test
=======================================

  asymmetric handshake (no PSK, 3-DH)                  ... PASS
  asymmetric: wrong peer pubkey → rejected           ... PASS

────────────────────────────────────────
Results: 2/2 passed, 0 failed
```

---

## 6. 性能基准测试

```bash
./bench-aegis
```

**x86_64 预期输出**：
```
AEGIS-128 Throughput Benchmark
==============================
Buffer size:  16 MiB
Iterations:   50

Pure C:          115 MB/s
x86 AES-NI:   [not available — compile with -maes]
NEON (plain): [not available on this platform]
ARM Crypto:   [not available on this platform]
```

**启用 AES-NI**：
```bash
gcc -std=c99 -D_GNU_SOURCE -DAEGIS_HAVE_AESNI -maes -msse2 -O3 -march=native \
    -I src -o bench-aegis-ni tests/bench_aegis.c \
    src/crypto/aegis.c src/crypto/x86/aegis128-x86.c src/util/util.c \
    -lssl -lcrypto
./bench-aegis-ni
# 预期：Pure C ~150 MB/s, AES-NI ~10000 MB/s (67x)
```

---

## 7. 端到端通信测试（PSK 模式）

### 7.1 准备

```bash
mkdir -p /tmp/aegis-test
dd if=/dev/urandom bs=16 count=1 of=/tmp/aegis-test/psk.key 2>/dev/null
chmod 400 /tmp/aegis-test/psk.key
```

### 7.2 终端 1：echo 服务器

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999))
s.listen(1)
print('[echo] 监听 :19999')
conn, _ = s.accept()
data = conn.recv(4096)
print(f'[echo] 收到: {data}')
conn.sendall(data)
conn.close()
"
```

### 7.3 终端 2：AEGIS 服务端

```bash
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -f /tmp/aegis-test/psk.key -m server -v
```

### 7.4 终端 3：AEGIS 客户端

```bash
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -f /tmp/aegis-test/psk.key -m client -v
```

### 7.5 终端 4：发送数据

```bash
echo "HELLO_AEGIS_TUNNEL" | nc -q 1 127.0.0.1 19001
```

**预期**：终端 4 输出 `HELLO_AEGIS_TUNNEL`

---

## 8. 非对称握手测试

### 8.1 生成密钥对

```bash
rm -rf /tmp/aegis-keys
./aegis-tunnel-keygen /tmp/aegis-keys/server
./aegis-tunnel-keygen /tmp/aegis-keys/client
```

### 8.2 服务端（非对称模式）

```bash
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P /tmp/aegis-keys/server/private.key \
    -Q /tmp/aegis-keys/client/public.key \
    -m server -v
```

### 8.3 客户端（非对称模式）

```bash
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -P /tmp/aegis-keys/client/private.key \
    -Q /tmp/aegis-keys/server/public.key \
    -m client -v
```

### 8.4 发送数据验证

```bash
echo "ASYMMETRIC_TEST" | nc -q 1 127.0.0.1 19001
```

### 8.5 错误公钥被拒绝

```bash
# 服务端用错误对端公钥
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P /tmp/aegis-keys/server/private.key \
    -Q /tmp/aegis-keys/server/public.key \   # ← 故意用服务端自己的公钥
    -m server -v
# 预期：客户端连接后握手失败
```

---

## 9. TOFU 自动交换公钥测试

### 9.1 清理旧数据

```bash
rm -rf ~/.aegis-tunnel
ls ~/.aegis-tunnel 2>&1  # 预期：No such file or directory
```

### 9.2 首次连接（自动生成密钥 + 交换公钥）

**终端 1** — echo 服务器（同上 7.2）

**终端 2** — 服务端（TOFU 模式）：
```bash
dd if=/dev/urandom bs=16 count=1 of=/tmp/psk-tofu.key 2>/dev/null
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -f /tmp/psk-tofu.key -m server -U -v
```

**终端 3** — 客户端（TOFU 模式）：
```bash
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -f /tmp/psk-tofu.key -m client -U -v
```

**关键日志**（首次连接）：
```
[tofu] generating new keypair in /home/.../.aegis-tunnel...
[tofu] keypair ready
[tofu] saved peer 127.0.0.1:19000
```

### 9.3 验证密钥存储

```bash
ls -la ~/.aegis-tunnel/
# 预期：private.key  public.key  known_hosts

cat ~/.aegis-tunnel/known_hosts
# 预期：127.0.0.1:19000 <64位hex公钥>
```

### 9.4 第二次连接（使用已存储公钥）

停止所有进程，重新启动。

**终端 2** — 服务端（TOFU 模式）：
```bash
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -f /tmp/psk-tofu.key -m server -U -v
```

**关键日志**（第二次连接）：
```
[INFO] TOFU: peer key found, using asymmetric auth   ← 不再生成新密钥
```

**终端 4** — 发送数据：
```bash
echo "TOFU_SECOND_CONNECTION" | nc -q 1 127.0.0.1 19001
```

### 9.5 模拟公钥变化测试

```bash
# 删除客户端的 TOFU 数据（模拟新设备）
rm -rf ~/.aegis-tunnel

# 重新连接 → 服务端 known_hosts 存的是旧公钥
# 客户端生成了新密钥对 → 服务端会检测到公钥不匹配
# 预期：握手会失败或产生安全告警
```

---

## 10. SOCKS5 透明代理测试

### 10.1 启动 HTTP 服务器

```bash
mkdir -p /tmp/aegis-www
echo "<h1>AEGIS-Tunnel OK</h1>" > /tmp/aegis-www/index.html
cd /tmp/aegis-www && python3 -m http.server 18080 &
HTTP_PID=$!
```

### 10.2 启动隧道（PSK 模式）

```bash
# 终端 2：服务端
./aegis-tunnel -l 19000 -r 127.0.0.1:18080 -f /tmp/aegis-test/psk.key -m server

# 终端 3：客户端
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 -f /tmp/aegis-test/psk.key -m client
```

### 10.3 通过 SOCKS5 访问

```bash
# curl
curl --proxy socks5h://127.0.0.1:19001 http://127.0.0.1:18080/
# 预期：<h1>AEGIS-Tunnel OK</h1>
```

### 10.4 清理

```bash
kill $HTTP_PID 2>/dev/null
pkill aegis-tunnel 2>/dev/null
```

---

## 11. TUN VPN 模式测试

**前置条件**：root 权限、`modprobe tun`。

### 11.1 服务端

```bash
sudo ./aegis-tunnel \
    -l 19000 -r 0.0.0.0:0 \
    -f /tmp/aegis-test/psk.key -m server \
    -T tun0 -I 10.0.0.1 -N 255.255.255.0 -R 10.0.0.0/24 -W eth0
```

### 11.2 客户端

```bash
sudo ./aegis-tunnel \
    -l 19000 -r <server-ip>:19000 \
    -f /tmp/aegis-test/psk.key -m client \
    -T tun0 -I 10.0.0.2 -N 255.255.255.0 -R 10.0.0.0/24
```

### 11.3 验证

```bash
ping 10.0.0.1        # 客户端 ping 服务端 TUN IP
sudo tcpdump -i tun0 -n   # 查看 tun0 流量
```

### 11.4 清理

```bash
sudo ip link del tun0
sudo iptables -t nat -F POSTROUTING
sudo iptables -F FORWARD
```

---

## 12. 抓包验证加密

### 12.1 启动隧道并抓包

```bash
# 终端 1：echo + 服务端 + 客户端

# 终端 2：抓加密端口
sudo tcpdump -i lo -X port 19000 | head -40 &

# 终端 3：抓明文端口（对比）
sudo tcpdump -i lo -X port 19999 | head -40 &
```

### 12.2 发送敏感数据

```bash
echo "TOP_SECRET_DATA_12345" | nc -q 1 127.0.0.1 19001
```

### 12.3 验证

| 端口 | 预期 |
|------|------|
| 19000 (加密隧道) | 密文乱码，搜索不到 `TOP_SECRET` |
| 19999 (明文 echo) | 明文可见 `TOP_SECRET_DATA_12345` |

---

## 13. 问题排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `No such file: test-aegis` | 未编译 | `make` |
| `cannot find -lssl` | 缺少 OpenSSL | `sudo apt install libssl-dev` |
| `TUNSETIFF failed` | 无 root 权限 | `sudo` |
| `cannot open /dev/net/tun` | TUN 模块未加载 | `sudo modprobe tun` |
| `handshake failed` | PSK 不匹配 | 检查两端密钥文件是否相同 |
| `make` 只生成一个文件 | `.o` 文件冲突 | `make clean && make` |
| 测试挂死 | 超时 | `timeout 10 ./test-tunnel` |
