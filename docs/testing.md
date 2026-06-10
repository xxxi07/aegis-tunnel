# AEGIS-Tunnel 测试指南

> 非对称 3-DH 握手模式。密钥自动生成，无需手动运行 keygen。

## 1. 快速开始

```bash
cd aegis-tunnel
make clean && make
```

**预期**：6 个二进制文件全部编译（aegis-tunnel、keygen、3 个测试、bench）。

## 2. 自动化测试（21 项）

```bash
make test
```

或逐个运行：

```bash
./test-aegis       # 加密算法：12/12
./test-tunnel      # 帧协议 + 握手：7/7
./e2e-test         # 端到端链路：2/2
./bench-aegis      # 性能基准
```

## 3. 生成密钥对（可选）

首次运行 `aegis-tunnel` 时会**自动生成**密钥对到 `~/.aegis-tunnel/`。

如果需要手动预生成（比如自动化部署脚本）：

```bash
./aegis-tunnel-keygen /etc/aegis/keys/
# → /etc/aegis/keys/private.key (chmod 400)
# → /etc/aegis/keys/public.key  (发给对端)
```

## 4. 端到端通信测试

### 4.1 自动密钥模式（推荐）

```bash
# 第一步：生成测试密钥对
rm -rf ~/.aegis-tunnel  # 清理旧数据

# 第二步：准备对端公钥
mkdir -p ~/.aegis-tunnel/peers

# 模拟服务端和客户端：先用 keygen 生成两对密钥，交换公钥
./aegis-tunnel-keygen /tmp/keys-server/
./aegis-tunnel-keygen /tmp/keys-client/

# 服务端：使用服务端私钥 + 客户端公钥
cp /tmp/keys-server/private.key ~/.aegis-tunnel/private.key
cp /tmp/keys-server/public.key ~/.aegis-tunnel/public.key
cp /tmp/keys-client/public.key ~/.aegis-tunnel/peers/127.0.0.1.pub

# 客户端（用另一个用户或另一台机器）：
# cp /tmp/keys-client/private.key ~/.aegis-tunnel/private.key
# cp /tmp/keys-server/public.key ~/.aegis-tunnel/peers/server-host.pub
```

### 4.2 显式密钥路径模式

**终端 1** — echo 服务器：
```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999)); s.listen(1)
conn, _ = s.accept(); data = conn.recv(4096); conn.sendall(data); conn.close()
print(f'echoed: {data}')
"
```

**终端 2** — 服务端：
```bash
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P /tmp/keys-server/private.key \
    -Q /tmp/keys-client/public.key \
    -m server -v
```

**终端 3** — 客户端：
```bash
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -P /tmp/keys-client/private.key \
    -Q /tmp/keys-server/public.key \
    -m client -v
```

**终端 4** — 发送数据：
```bash
echo "HELLO_AEGIS" | nc -q 1 127.0.0.1 19001
# 预期：输出 HELLO_AEGIS
```

## 5. 错误公钥被拒绝

```bash
# 服务端故意用自己的公钥作为对端公钥（应该失败）
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P /tmp/keys-server/private.key \
    -Q /tmp/keys-server/public.key \
    -m server -v
# 预期：客户端连接后握手失败
```

## 6. 性能基准

```bash
./bench-aegis
# 纯 C ~115 MB/s

# 启用 AES-NI 加速：
gcc -std=c99 -D_GNU_SOURCE -DAEGIS_HAVE_AESNI -maes -msse2 -O3 -march=native \
    -I src -o bench-ni tests/bench_aegis.c \
    src/crypto/aegis.c src/crypto/x86/aegis128-x86.c src/util/util.c -lssl -lcrypto
./bench-ni
# 预期：~10 GB/s（67x 加速）
```

## 7. 问题排查

| 现象 | 解决 |
|------|------|
| `peer key not found` | `cp peer.pub ~/.aegis-tunnel/peers/<host>.pub` |
| `handshake failed` | 对端公钥不匹配，检查 `-Q` 指向的 pub 文件 |
| `make` 只生成一个文件 | `make clean && make` |
| `cannot find -lssl` | `sudo apt install libssl-dev` |
