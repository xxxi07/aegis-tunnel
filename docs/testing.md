# AEGIS-Tunnel 测试指南

> 非对称握手模式。使用 `aegis-tunnel-keygen` 生成密钥对。

## 1. 快速开始

```bash
cd aegis-tunnel
make clean && make
```

**预期**：6 个二进制文件编译成功。

## 2. 单元测试

### 2.1 加密算法 (`test-aegis`) — 12 项

```bash
./test-aegis
# 预期：12/12 passed, 0 failed
```

### 2.2 帧协议 + 握手 (`test-tunnel`) — 7 项

```bash
timeout 10 ./test-tunnel
# 预期：7/7 passed, 0 failed
```

### 2.3 端到端 (`e2e-test`) — 2 项

```bash
timeout 10 ./e2e-test
# 预期：2/2 passed, 0 failed
```

## 3. 性能基准

```bash
./bench-aegis
# 纯 C ~115 MB/s（启用 AES-NI 可达 ~10 GB/s）
```

## 4. 生成密钥对

```bash
./aegis-tunnel-keygen /tmp/server-keys/
./aegis-tunnel-keygen /tmp/client-keys/

# 交换 public.key：服务端需要客户端的公钥，客户端需要服务端的公钥
```

## 5. 端到端通信测试

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
    -P /tmp/server-keys/private.key \
    -Q /tmp/client-keys/public.key \
    -m server -v
```

**终端 3** — 客户端：
```bash
./aegis-tunnel -l 19001 -r 127.0.0.1:19000 \
    -P /tmp/client-keys/private.key \
    -Q /tmp/server-keys/public.key \
    -m client -v
```

**终端 4** — 发送数据：
```bash
echo "HELLO_AEGIS" | nc -q 1 127.0.0.1 19001
# 预期：输出 HELLO_AEGIS
```

## 6. 错误公钥被拒绝

```bash
# 服务端故意用自己的公钥（应该失败）
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 \
    -P /tmp/server-keys/private.key \
    -Q /tmp/server-keys/public.key \
    -m server -v
# 预期：客户端连接后握手失败
```

## 7. 问题排查

| 现象 | 解决 |
|------|------|
| `-P/-Q required` | 需要生成密钥对并用 `-P` `-Q` 指定 |
| `handshake failed` | 对端公钥不匹配，检查 `-Q` 是否指向正确的 public.key |
| `cannot find -lssl` | `sudo apt install libssl-dev` |
| `make` 只生成一个文件 | `make clean && make` |
