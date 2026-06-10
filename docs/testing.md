# AEGIS-Tunnel 完整测试指南

## 前提

```bash
# 安装依赖（Ubuntu/Debian）
sudo apt install -y gcc make libssl-dev

# 克隆项目
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
```

---

## 第 1 步：编译

```bash
make clean && make
```

**预期输出**：6 行 `→ xxx built`

```bash
# 确认所有文件存在
ls -la aegis-tunnel aegis-tunnel-keygen test-aegis test-tunnel e2e-test bench-aegis
```

**预期**：6 个文件全部存在，无 "No such file" 错误。

---

## 第 2 步：单元测试（21 项，全部自动化，无需外部依赖）

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

### 2.2 帧协议 + 握手 — 7 项

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

**预期**：输出纯 C 吞吐量（x86_64 约 115 MB/s）。

---

## 第 3 步：端到端加密通信测试（3 个终端）

### 3.1 准备密钥

```bash
# 清理旧数据，模拟全新环境
rm -rf ~/.aegis-tunnel /tmp/keys-test
```

### 3.2 终端 1 — 启动 echo 服务器

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

### 3.3 生成密钥 + 交换公钥

```bash
rm -rf ~/.aegis-tunnel

# 一行生成密钥
./aegis-tunnel keygen
# 输出：Public key (send to peer):
#         a1b2c3d4e5f6...

# 一行添加对端公钥
./aegis-tunnel peer add pi a1b2c3d4e5f6...

# 查看已知对端
./aegis-tunnel peer list
```

### 3.5 终端 2 — 启动服务端

```bash
rm -rf ~/.aegis-tunnel
cp -r /tmp/keys-test/server-keys ~/.aegis-tunnel
mkdir -p ~/.aegis-tunnel/peers
cat /tmp/keys-test/client-keys/public.key > ~/.aegis-tunnel/peers/client.pub

./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P ~/.aegis-tunnel/private.key \
    -Q ~/.aegis-tunnel/peers/client.pub \
    -m server -v
```

**预期**：无 handshake failed 错误。

### 3.6 终端 3 — 启动客户端

```bash
rm -rf ~/.aegis-tunnel
cp -r /tmp/keys-test/client-keys ~/.aegis-tunnel
mkdir -p ~/.aegis-tunnel/peers
cat /tmp/keys-test/server-keys/public.key > ~/.aegis-tunnel/peers/127.0.0.1.pub

./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -P ~/.aegis-tunnel/private.key \
    -Q ~/.aegis-tunnel/peers/127.0.0.1.pub \
    -m client -v
```

**预期**：`handshake completed`，无错误。

### 3.7 终端 4 — 发送加密数据

```bash
echo "HELLO_AEGIS_TUNNEL" | nc -q 1 127.0.0.1 19001
```

**预期**：输出 `HELLO_AEGIS_TUNNEL`。

同时查看终端 1（echo 服务器）输出：
```
[echo] received: b'HELLO_AEGIS_TUNNEL\n'
```

---

## 第 4 步：错误公钥被拒绝

```bash
# 服务端故意用自己的公钥作为对端公钥
SERVER_KEY=$(cat /tmp/keys-test/server-keys/public.key)

rm -rf ~/.aegis-tunnel
cp -r /tmp/keys-test/server-keys ~/.aegis-tunnel
mkdir -p ~/.aegis-tunnel/peers
echo "$SERVER_KEY" > ~/.aegis-tunnel/peers/client.pub

# 尝试连接 → 应该失败
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P ~/.aegis-tunnel/private.key \
    -Q ~/.aegis-tunnel/peers/client.pub \
    -m server -v
# 预期：客户端连接后握手失败
```

---

## 第 5 步：清理

```bash
pkill aegis-tunnel 2>/dev/null
pkill "python3 -c" 2>/dev/null
rm -rf /tmp/keys-test
```

---

## 一键测试脚本

```bash
#!/bin/bash
# 保存为 scripts/test-all.sh 并运行
cd "$(dirname "$0")/.."
FAIL=0

echo "═══ 1. 编译 ═══"
make clean > /dev/null 2>&1
make 2>&1 | grep "→" || ((FAIL++))

echo "═══ 2. 算法测试 ═══"
timeout 10 ./test-aegis 2>&1 | grep -q "12/12 passed" || ((FAIL++))

echo "═══ 3. 协议测试 ═══"
timeout 10 ./test-tunnel 2>&1 | grep -q "7/7 passed" || ((FAIL++))

echo "═══ 4. 端到端测试 ═══"
timeout 10 ./e2e-test 2>&1 | grep -q "2/2 passed" || ((FAIL++))

echo "═══ 5. 主程序验证 ═══"
./aegis-tunnel -h > /dev/null 2>&1 || ((FAIL++))
rm -rf ~/.aegis-tunnel
timeout 2 ./aegis-tunnel -l 19990 -r test:9000 2>&1 | grep -q "No peer key" || ((FAIL++))

if [ $FAIL -eq 0 ]; then
    echo "═══ 全部通过 ═══"
else
    echo "═══ $FAIL 项失败 ═══"
fi
exit $FAIL
```
