# AEGIS-Tunnel 测试指南

## 目录

1. [编译](#1-编译)
2. [单元测试](#2-单元测试)
3. [性能基准](#3-性能基准)
4. [端到端通信测试](#4-端到端通信测试)
5. [SOCKS5 代理测试](#5-socks5-代理测试)
6. [非对称握手测试](#6-非对称握手测试)
7. [抓包验证](#7-抓包验证)
8. [TUN VPN 模式测试](#8-tun-vpn-模式测试)
9. [一键全量测试脚本](#9-一键全量测试脚本)
10. [测试用例清单](#10-测试用例清单)

---

## 1. 编译

```bash
cd /home/xixt5127/projects/aegis-tunnel

# 方式 A：Makefile（推荐，无需 CMake）
make clean
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel

# 方式 B：CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 方式 C：手动 gcc
gcc -std=c99 -D_GNU_SOURCE -I src -O2 \
    -o aegis-tunnel \
    src/main.c src/tunnel/tunnel.c src/tunnel/tun.c \
    src/tunnel/threadpool.c src/protocol/frame_reader.c \
    src/protocol/handshake.c src/protocol/ecdh.c \
    src/crypto/aegis.c src/util/util.c src/util/log.c src/util/config.c \
    -lssl -lcrypto -lpthread
```

---

## 2. 单元测试

### 2.1 加密算法层 (`test-aegis`) — 13 项

测试 AEGIS-128 AEAD 实现的正确性。

```bash
make test-aegis && ./test-aegis
```

| # | 测试名称 | 验证内容 |
|---|---------|---------|
| 1 | empty message, empty AD | 空消息 + 空关联数据加解密回环 |
| 2 | single block (16 bytes), no AD | 单块消息加解密 |
| 3 | multi-block (47 bytes) with AD (8 bytes) | 多块消息 + 关联数据 |
| 4 | large message (1024 bytes) with large AD (256 bytes) | 大数据量加解密 |
| 5 | wrong key → authentication failure | 错误密钥必须被拒绝 |
| 6 | corrupted tag → authentication failure | 损坏的认证标签必须被检测 |
| 7 | corrupted ciphertext → authentication failure | 损坏的密文必须导致认证失败 |
| 8 | wrong AD → authentication failure | 关联数据不匹配必须被检测 |
| 9 | in-place encrypt/decrypt (buffer aliasing) | 原地加解密（dst == src） |
| 10 | streaming API roundtrip | 流式 API 分块加解密 |
| 11 | different keys → different ciphertexts | 不同密钥产生不同输出 |
| 12 | deterministic: same inputs → same output | 相同输入产生相同输出 |
| 13 | x86 AES-NI ≡ pure C (cross-validation) | x86 AES-NI 输出与纯 C 一致 |

**预期输出**：
```
Results: 13/13 passed, 0 failed
```

### 2.2 帧协议层 (`test-tunnel`) — 7 项

测试 AEGIS-Tunnel 帧协议和 PSK 握手。

```bash
make test-tunnel && ./test-tunnel
```

| # | 测试名称 | 验证内容 |
|---|---------|---------|
| 1 | frame build → parse roundtrip (DATA, 100 bytes) | 帧构建→加密→解密回环 |
| 2 | frame parse rejects wrong nonce counter | Nonce 计数器不匹配必须拒绝 |
| 3 | frame build → parse KEEPALIVE (zero payload) | 零负载心跳帧 |
| 4 | handshake + data transfer (end-to-end) | PSK 握手 + 加密数据传输 |
| 5 | wrong PSK → handshake rejected | 错误 PSK 必须导致握手失败 |
| 6 | large frame (65535 bytes) roundtrip | 最大帧(65535字节)回环 |
| 7 | corrupted frame tag → rejected | 帧认证标签损坏必须拒绝 |

**预期输出**：
```
Results: 7/7 passed, 0 failed
```

### 2.3 端到端协议 (`e2e-test`) — 2 项

测试完整链路：握手 → 加密 → echo → 解密。

```bash
make e2e-test && ./e2e-test
```

| # | 测试名称 | 验证内容 |
|---|---------|---------|
| 1 | handshake + key derivation + encrypt + decrypt | ECDH 密钥协商 + 加解密回环 |
| 2 | wrong PSK → handshake rejected | 错误 PSK 拒绝 |

**预期输出**：
```
Results: 2/2 passed, 0 failed
```

### 2.4 非对称握手 (`test-asymmetric`) — 2 项

测试 WireGuard 风格的 3-DH 非对称握手。

```bash
make test-asymmetric && ./test-asymmetric
```

| # | 测试名称 | 验证内容 |
|---|---------|---------|
| 1 | asymmetric handshake (no PSK, 3-DH) | 非对称密钥协商 + 会话密钥一致性 |
| 2 | wrong peer pubkey → rejected | 错误对端公钥必须拒绝 |

**预期输出**：
```
Results: 2/2 passed, 0 failed
```

---

## 3. 性能基准

```bash
make bench-aegis && ./bench-aegis
```

**x86_64 (AMD Ryzen / Intel Core) 预期输出**：
```
AEGIS-128 Throughput Benchmark
==============================
Buffer size:  16 MiB
Iterations:   50

Pure C:          141 MB/s
x86 AES-NI:     9558 MB/s  (67.6x)  ← 硬件 AES 加速
NEON (plain):    [not available on x86_64]
ARM Crypto:      [not available on x86_64]
```

**ARM 树莓派 3 (Cortex-A53, 无 AES) 预期输出**：
```
Pure C:          180 MB/s
NEON (plain):    350 MB/s  (1.9x)   ← Plain NEON 加速
ARM Crypto:      [not available]
```

**ARM 树莓派 5 (Cortex-A76, 有 AES) 预期输出**：
```
Pure C:          250 MB/s
NEON (plain):    500 MB/s  (2.0x)
ARM Crypto:     1200 MB/s  (4.8x)   ← 硬件 AES 加速
```

---

## 4. 端到端通信测试

验证客户端和服务端之间加密通信的完整流程。

### 4.1 准备

```bash
# 生成 PSK 密钥（16 字节随机数）
dd if=/dev/urandom bs=16 count=1 of=/tmp/psk.key 2>/dev/null
chmod 400 /tmp/psk.key
```

### 4.2 启动 echo 服务器

```bash
# 终端 1：启动一个简单的 TCP echo 服务
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999))
s.listen(1)
print('[echo] listening on :19999')
conn, addr = s.accept()
print(f'[echo] connected from {addr}')
data = conn.recv(4096)
print(f'[echo] received: {data}')
conn.sendall(data)
conn.close()
s.close()
"
```

### 4.3 服务端

```bash
# 终端 2：启动 AEGIS-Tunnel 服务端
./aegis-tunnel \
    -l 19000 \
    -r 127.0.0.1:19999 \
    -f /tmp/psk.key \
    -m server \
    -v
```

输出示例：
```
[server] port 19000 → 127.0.0.1:19999 (max 32 connections)
[20:15:30.123] [INFO ] [server] #1 127.0.0.1:45678
[20:15:30.125] [INFO ] [server] handshake completed
```

### 4.4 客户端

```bash
# 终端 3：启动 AEGIS-Tunnel 客户端
./aegis-tunnel \
    -l 19001 \
    -r 127.0.0.1:19000 \
    -f /tmp/psk.key \
    -m client \
    -v &

# 等待客户端启动
sleep 1

# 通过隧道发送数据
echo "HELLO_AEGIS_TUNNEL" | nc -q 1 127.0.0.1 19001
```

**预期结果**：客户端终端输出 `HELLO_AEGIS_TUNNEL`，证明数据经过加密隧道完整回环。

---

## 5. SOCKS5 代理测试

验证业务应用通过 SOCKS5 代理零修改接入加密隧道。

### 5.1 准备工作

```bash
# 确保有 nc 工具支持 SOCKS5
# Debian/Ubuntu: sudo apt install ncat
# 或使用 curl（自带 SOCKS5 支持）
```

### 5.2 启动服务端

```bash
# 终端 1：启动 HTTP 测试服务器
python3 -m http.server 18080 &
HTTP_PID=$!

# 终端 2：启动 AEGIS-Tunnel 服务端
./aegis-tunnel \
    -l 19000 -r 127.0.0.1:18080 \
    -f /tmp/psk.key -m server

# 终端 3：启动 AEGIS-Tunnel 客户端
./aegis-tunnel \
    -l 19001 -r 127.0.0.1:19000 \
    -f /tmp/psk.key -m client
```

### 5.3 通过 SOCKS5 访问

```bash
# 方式 A：curl（推荐）
curl --proxy socks5h://127.0.0.1:19001 http://example.com/
# `socks5h` 中的 h 表示 DNS 解析也在代理端进行

# 方式 B：浏览器
# Firefox → 设置 → 网络设置 → SOCKS 代理
#   主机: 127.0.0.1  端口: 19001
#   类型: SOCKS5
#   勾选: 使用 SOCKS v5 时代理 DNS 查询

# 方式 C：ssh 通过 SOCKS5
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:19001 %h %p' user@remote-server
```

### 5.4 清理

```bash
kill $HTTP_PID 2>/dev/null
pkill aegis-tunnel 2>/dev/null
```

---

## 6. 非对称握手测试

### 6.1 生成密钥对

```bash
# 为服务端生成密钥对
./aegis-tunnel-keygen /tmp/server-keys/
# 输出:
#   /tmp/server-keys/private.key  (chmod 400 — 保密)
#   /tmp/server-keys/public.key   (分享给客户端)

# 为客户端生成密钥对
./aegis-tunnel-keygen /tmp/client-keys/
# 输出:
#   /tmp/client-keys/private.key  (chmod 400 — 保密)
#   /tmp/client-keys/public.key   (分享给服务端)
```

### 6.2 运行测试

```bash
make test-asymmetric && ./test-asymmetric
```

**预期输出**：
```
AEGIS-Tunnel Asymmetric Handshake Test
=======================================

  asymmetric handshake (no PSK, 3-DH)                  ... PASS
  asymmetric: wrong peer pubkey → rejected           ... PASS

Results: 2/2 passed, 0 failed
```

---

## 7. 抓包验证

验证网络链路上的数据确实是密文。

### 7.1 启动隧道

```bash
# 终端 1：启动 echo + 服务端 + 客户端（同第 4 节）
```

### 7.2 抓包

```bash
# 终端 2：在服务端隧道端口抓包
sudo tcpdump -i lo -X port 19000
```

### 7.3 发送明文并对比

```bash
# 终端 3：发送数据
echo "TOP_SECRET_DATA_12345" | nc -q 1 127.0.0.1 19001
```

**预期结果**：tcpdump 输出是乱码，搜索不到 `TOP_SECRET_DATA_12345` 字符串。

```hex
# 正常抓包应该是这样的密文数据：
0x0000:  0200 0050 8a3f 7c1d e2b5 9f4a  ...   ← 帧类型 0x02 (DATA)
0x0010:  c71e d308 6bd4 f9e3 7284 1acf  ...   ← AEGIS 加密的负载
0x0020:  5e2b 941f                           ← 认证标签
```

### 7.4 验证方法

| 检查项 | 预期 |
|--------|------|
| 帧类型字节 | 第二字节为 `0x02` (DATA) |
| 负载内容 | 完全不可读，无明文特征 |
| 认证标签 | 最后 16 字节存在 |
| 明文搜索 | `grep "TOP_SECRET"` 无结果 |

---

## 8. TUN VPN 模式测试

TUN 模式创建虚拟网卡，实现真正的 Layer 3 VPN。

**前置条件**：
```bash
# 需要 root 权限，内核 tun 模块
sudo modprobe tun
ls /dev/net/tun   # 确认存在
```

### 8.1 服务端

```bash
# 终端 1：启动 TUN VPN 服务端
sudo ./aegis-tunnel \
    -l 19000 -r 0.0.0.0:0 \
    -f /tmp/psk.key -m server \
    -T tun0 -I 10.0.0.1 -N 255.255.255.0 -R 10.0.0.0/24 -W eth0
```

**自动执行的操作**：
1. 创建 `tun0` 虚拟网卡
2. 配置 IP `10.0.0.1/24`
3. 启用网卡
4. 添加路由 `10.0.0.0/24`
5. 启用 IP 转发
6. 添加 iptables NAT 规则（MASQUERADE）
7. 添加 iptables FORWARD 规则

### 8.2 客户端

```bash
# 终端 2：启动 TUN VPN 客户端
sudo ./aegis-tunnel \
    -l 19000 -r <server-ip>:19000 \
    -f /tmp/psk.key -m client \
    -T tun0 -I 10.0.0.2 -N 255.255.255.0 -R 10.0.0.0/24
```

### 8.3 验证

```bash
# 客户端 ping 服务端 tun0
ping 10.0.0.1
# 预期：有响应，延迟正常

# 服务端 ping 客户端 tun0
ping 10.0.0.2
# 预期：有响应

# 查看 tun0 流量
sudo tcpdump -i tun0 -n
# 预期：看到 ICMP (ping) 包

# 客户端通过 VPN 访问服务端所在网络
# 如果服务端 eth0 能访问外网，客户端也能
curl --interface tun0 http://example.com
```

### 8.4 配置文件方式

```bash
# 服务端
sudo ./aegis-tunnel -C deploy/tun-server.conf.example -f /tmp/psk.key

# 客户端
sudo ./aegis-tunnel -C deploy/tun-client.conf.example -f /tmp/psk.key
```

### 8.5 清理

```bash
sudo ip link del tun0 2>/dev/null
sudo iptables -t nat -F POSTROUTING 2>/dev/null
sudo iptables -F FORWARD 2>/dev/null
```

---

## 9. 一键全量测试脚本

```bash
#!/bin/bash
# 保存为 scripts/test-all.sh
set -e
cd "$(dirname "$0")/.."
FAIL=0
PASS=0

run_test() {
    local name="$1" cmd="$2"
    printf "  %-55s ... " "$name"
    if eval "$cmd" > /dev/null 2>&1; then
        echo "PASS"; ((PASS++))
    else
        echo "FAIL"; ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. 编译 ──
echo "── 1. 编译 ──"
make clean > /dev/null 2>&1
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel 2>&1 | tail -3
echo ""

# ── 2. 算法测试 ──
echo "── 2. AEGIS-128 算法 (13项) ──"
timeout 10 ./test-aegis
echo ""

# ── 3. 协议测试 ──
echo "── 3. 帧协议 + PSK 握手 (7项) ──"
timeout 10 ./test-tunnel
echo ""

# ── 4. 端到端测试 ──
echo "── 4. 端到端握手+加解密 (2项) ──"
timeout 10 ./e2e-test
echo ""

# ── 5. 非对称握手测试 ──
echo "── 5. 非对称握手 (2项) ──"
make test-asymmetric 2>&1 | tail -1
timeout 10 ./test-asymmetric 2>/dev/null || echo "  (build test-asymmetric first: make test-asymmetric)"
echo ""

# ── 6. 性能测试 ──
echo "── 6. 性能基准 ──"
./bench-aegis 2>&1 | head -7
echo ""

# ── 7. 主程序功能验证 ──
echo "── 7. 主程序 smoke test ──"
run_test "help output"          "./aegis-tunnel -h > /dev/null"
run_test "PSK file read"        "./aegis-tunnel -l 19990 -r 127.0.0.1:80 -f /tmp/psk.key -h > /dev/null"
run_test "parameter validation" "./aegis-tunnel 2>&1 | grep -q 'Error'"
run_test "TUN help"             "./aegis-tunnel -h 2>&1 | grep -q '\-T'"
echo ""

# ── 总结 ──
echo "═══════════════════════════════════════════"
echo " Results: $((PASS + FAIL)) total, $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"

exit $FAIL
```

使用方式：
```bash
chmod +x scripts/test-all.sh
./scripts/test-all.sh
```

---

## 10. 测试用例清单

### 10.1 加密算法

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| A01 | 空消息加解密 | ciphertext 空，tag 正确，解密成功 |
| A02 | 单块消息加解密 | 16 字节加解密回环一致 |
| A03 | 多块消息 + AD | 47 字节 + 8 字节 AD 回环一致 |
| A04 | 大数据量加解密 | 1024 字节 + 256 字节 AD 回环一致 |
| A05 | 错误密钥 | 解密返回 -1，输出清零 |
| A06 | 损坏认证标签 | tag[5] ^= 0x01，解密返回 -1 |
| A07 | 损坏密文 | ct[10] ^= 0x01，解密返回 -1 |
| A08 | AD 不匹配 | 不同 AD，解密返回 -1 |
| A09 | 原地加解密 | dst == src 时回环正确 |
| A10 | 流式 API | 分 3 块 AD + 3 块明文，回环正确 |
| A11 | 密钥变化性 | 不同 key 产生不同 ct 和 tag |
| A12 | 确定性 | 相同输入两次加密结果一致 |
| A13 | x86 AES-NI 交叉验证 | AES-NI 输出 ≡ 纯 C 输出 |

### 10.2 帧协议

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| F01 | 帧构建→解析 | 100 字节加密→解密回环一致 |
| F02 | Nonce 验证 | 错误 nonce 导致认证失败 |
| F03 | KEEPALIVE 帧 | 零负载帧正确构建和解析 |
| F04 | PSK 握手+传输 | 双线程握手 + 加密数据收发 |
| F05 | PSK 错误拒绝 | 不同 PSK 握手失败 |
| F06 | 大帧回环 | 65535 字节帧正确回环 |
| F07 | 标签损坏 | 帧 tag 损坏必须拒绝 |

### 10.3 端到端握手

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| E01 | 完整链路 | 握手→密钥协商→加密→echo→解密，多消息(含65535字节) |
| E02 | 错误 PSK | 握手失败，连接关闭 |

### 10.4 非对称握手

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| N01 | 3-DH 协商 | 双方会话密钥一致，KEYCONFIRM 通过 |
| N02 | 错误公钥 | 对端公钥错误必须拒绝 |

### 10.5 性能

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| P01 | 纯 C 基准 | 吞吐量 > 50 MB/s |
| P02 | AES-NI 基准 | 加速比 > 50x |
| P03 | NEON 基准 | ARM 上加速比 > 1.5x (待 ARM 硬件验证) |
| P04 | ARM Crypto 基准 | ARM+ AES 上加速比 > 3x (待 ARM 硬件验证) |

### 10.6 安全

| 编号 | 测试项 | 通过标准 |
|------|--------|---------|
| S01 | 常量时间比较 | `memcmp_constant` 不短路 |
| S02 | 敏感数据清零 | `secure_memzero` 不被编译器优化 |
| S03 | Nonce 唯一性 | 每次加密 nonce 递增 |
| S04 | 前向安全 | 握手后临时私钥已销毁 |
| S05 | 密钥确认 | KEYCONFIRM 帧双向验证 |
| S06 | 重协商 | 120 秒自动 REKEY |

---

## 测试环境要求

| 环境 | 适用测试 |
|------|---------|
| x86_64 Linux (普通用户) | 全部单元测试、端到端测试、性能基准 |
| x86_64 Linux (root) | TUN 模式、tcpdump 抓包 |
| ARM 树莓派 3 (无 AES) | Plain NEON 性能基准 |
| ARM 树莓派 4/5 (有 AES) | ARM Crypto 性能基准 |
| Apple M1/M2 (macOS) | ARM Crypto 性能基准 (需适配 UTUN) |
