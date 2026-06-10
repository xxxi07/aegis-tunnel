# AEGIS-Tunnel 完整测试指南

## 前提

```bash
sudo apt install -y gcc make libssl-dev
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
```

## 第 1 步：编译

```bash
make clean && make
```

**预期**：6 行 `→ xxx built`
```bash
ls -la aegis-tunnel test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel-keygen
# 6 个文件全部存在
```

## 第 2 步：自动化测试（21 项，3 个进程内测试）

### 2.1 加密算法 — 12 项

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
  streaming API roundtrip                       ... PASS
  different keys → different ciphertexts      ... PASS
  deterministic: same inputs → same output      ... PASS

────────────────────────────────────────
Results: 12/12 passed, 0 failed
```

### 2.2 帧协议 + 非对称握手 — 7 项

```bash
./test-tunnel
```

**完整预期输出**：
```
AEGIS-Tunnel Integration Tests
==============================

  frame build → parse roundtrip (DATA, 100 bytes)  ... PASS
  frame parse rejects wrong nonce counter            ... PASS
  frame build → parse KEEPALIVE (zero payload)     ... PASS
  handshake + data transfer (end-to-end)             ... PASS
  wrong peer pubkey → handshake rejected           ... PASS
  large frame (65535 bytes) roundtrip                ... PASS
  corrupted frame tag → rejected                   ... PASS

Results: 7/7 passed, 0 failed
```

### 2.3 端到端 — 2 项

```bash
./e2e-test
```

**完整预期输出**：
```
AEGIS-Tunnel End-to-End Test
=============================

  handshake + key derivation + encrypt + decrypt       ... PASS
  wrong peer pubkey → handshake rejected             ... PASS

Results: 2/2 passed, 0 failed
```

### 2.4 性能基准

```bash
./bench-aegis
```

x86_64 预期：纯 C ~115 MB/s。

---

## 第 3 步：子命令测试

```bash
# 3.1 生成密钥（一行）
rm -rf ~/.aegis-tunnel
./aegis-tunnel keygen
```

**预期输出**：
```
Keys generated in /home/user/.aegis-tunnel
Public key (send to peer):
  a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

Next: get peer's public key, then:
  aegis-tunnel peer add <hostname> <peer-hex-key>
```

```bash
# 3.2 添加对端公钥（一行）
./aegis-tunnel peer add server.com a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
# 预期：Peer 'server.com' added.

# 3.3 验证 hex 长度校验
./aegis-tunnel peer add bad abc
# 预期：Error: hex key must be 64 characters (got 3)

# 3.4 查看状态
./aegis-tunnel status
```

**预期输出**：
```
Key storage: /home/user/.aegis-tunnel
  Private key: /home/user/.aegis-tunnel/private.key (exists)
  Public key:  /home/user/.aegis-tunnel/public.key (exists)
Known peers:
  server.com
```

```bash
# 3.5 查看已知对端
./aegis-tunnel peer list
# 预期：server.com
```

---

## 第 4 步：端到端加密通信（4 个终端）

测试完整的客户端↔服务端加密数据回环。

### 4.1 准备工作

```bash
rm -rf ~/.aegis-tunnel

# 生成密钥对
./aegis-tunnel keygen
# 记下输出的 public key hex
```

### 4.2 终端 1 — echo 服务器

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999))
s.listen(1)
print('[echo] listening on :19999')
conn, _ = s.accept()
data = conn.recv(4096)
print(f'[echo] received: {data}')
conn.sendall(data)
conn.close()
print('[echo] done')
"
```

### 4.3 终端 2 — 服务端

```bash
# 生成服务端密钥，添加客户端公钥
rm -rf ~/.aegis-tunnel
./aegis-tunnel keygen > /tmp/server-key.txt 2>&1
SERVER_KEY=$(grep "^  [a-f0-9]" /tmp/server-key.txt | tr -d ' ')
echo "服务端公钥: $SERVER_KEY"

# 添加客户端公钥（用终端 3 的客户端公钥替换下面的值）
./aegis-tunnel peer add client <客户端公钥hex>

# 启动服务端
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 -m server -v
```

### 4.4 终端 3 — 客户端

```bash
# 生成客户端密钥，添加服务端公钥
rm -rf ~/.aegis-tunnel
./aegis-tunnel keygen > /tmp/client-key.txt 2>&1
CLIENT_KEY=$(grep "^  [a-f0-9]" /tmp/client-key.txt | tr -d ' ')
echo "客户端公钥: $CLIENT_KEY"

# 添加服务端公钥
./aegis-tunnel peer add server $SERVER_KEY

# 启动客户端
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 -m client -v
```

### 4.5 终端 4 — 发送数据

```bash
echo "HELLO_AEGIS_TUNNEL" | nc -q 1 127.0.0.1 19001
```

**预期**：输出 `HELLO_AEGIS_TUNNEL`

终端 1 输出：`[echo] received: b'HELLO_AEGIS_TUNNEL\n'`

---

## 第 5 步：错误公钥拒绝测试

```bash
# 服务端用另一个不匹配的公钥
./aegis-tunnel peer add bad ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

# 客户端尝试连接（用 bad 公钥匹配的服务端）
# 预期：握手失败，handshake failed
```

---

## 第 6 步：配置文件模式测试

### 6.1 创建配置文件

```bash
cat > /tmp/aegis-test.conf << 'EOF'
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
Port = 7777
Mode = server

[Peer]
PublicKey = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Endpoint = 127.0.0.1:19999

[Tunnel]
Keepalive = 30
EOF
```

### 6.2 用配置文件启动

```bash
./aegis-tunnel -c /tmp/aegis-test.conf -v 2>&1 | head -5
```

**预期**：`[INFO] loaded config from /tmp/aegis-test.conf`

---

## 第 7 步：TUN VPN 模式测试（需 root）

### 7.1 前置

```bash
sudo modprobe tun
ls /dev/net/tun  # 确认存在
```

### 7.2 服务端（全隧道模式）

```bash
sudo ./aegis-tunnel -T 10.0.0.1/24 -W eth0 -m server -v 2>&1 | head -10
```

**预期输出**：
```
[tun] created device: tun0 (fd=5)
[tun] tun0: 10.0.0.1/24
[tun] IP forwarding: enabled
[tun] NAT: 10.0.0.0/24 → eth0 (MASQUERADE)
[tun] FORWARD rules: tun0 → ACCEPT
```

### 7.3 客户端（全隧道模式）

```bash
# 在另一台机器或本地另一个终端
sudo ./aegis-tunnel -T 10.0.0.2/24 -m client -v
```

### 7.4 验证

```bash
ping 10.0.0.1              # 客户端 ping 服务端 TUN IP
sudo tcpdump -i tun0 -n -c 5  # 查看 tun0 上的 IP 流量
```

### 7.5 全隧道模式（所有流量走 VPN）

```bash
# 修改配置文件或命令行参数
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client
# 所有流量走加密隧道
# 验证：curl ifconfig.me → 应该显示服务端的公网 IP
```

### 7.6 清理

```bash
sudo ./aegis-tunnel tun down
# 预期：TUN tun0 removed, routes and iptables cleared.
```

---

## 第 8 步：抓包验证加密

```bash
# 终端 1：抓隧道端口
sudo tcpdump -i lo -X port 19000 2>&1 | head -20 &

# 终端 2：发送数据
echo "TOP_SECRET" | nc -q 1 127.0.0.1 19001

# 验证：tcpdump 输出中搜索不到 "TOP_SECRET"
```

---

## 第 9 步：一键测试脚本

```bash
bash scripts/test-all.sh
```

**预期**：全部通过，无 FAIL。

---

## 问题排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `peer key not found` | 未添加对端公钥 | `./aegis-tunnel peer add <host> <hex>` |
| `handshake failed` | 对端公钥不匹配 | 检查双方公钥是否正确 |
| `TUNSETIFF: Operation not permitted` | 无 root 权限 | `sudo` |
| `/dev/net/tun: No such file` | TUN 模块未加载 | `sudo modprobe tun` |
| `bind: Address already in use` | 端口被占用 | 换端口 `-l 9001` |
| `hex key must be 64 characters` | 公钥长度错误 | 检查复制的 hex 是否完整 |
| `make` 只生成一个文件 | `.o` 缓存冲突 | `make clean && make` |
| `cannot find -lssl` | 缺少 OpenSSL | `sudo apt install libssl-dev` |
