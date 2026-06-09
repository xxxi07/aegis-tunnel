# AEGIS-Tunnel

基于 **AEGIS-128** 认证加密的轻量级安全隧道，支持 ARM NEON 原生加速。

## 概述

AEGIS-Tunnel 是一个极简的加密隧道工具，在 TCP 之上提供 AEGIS-128 认证加密传输。适用于嵌入式设备、边缘计算和个人使用场景。

### 特性

- **极简协议**：~2000 行 C99 代码，易于审计和定制
- **AEGIS-128 AEAD**：CAESAR 竞赛冠军算法，提供认证加密
- **ARM NEON 加速**：使用 NEON `tbl`/`tbx` 指令实现 Plain NEON 路径，无需硬件 AES
- **PSK 握手**：预共享密钥认证，带时间戳防重放
- **独立可发布**：不依赖内核模块或大型框架

### 与竞品对比

| 特性 | WireGuard | OpenVPN | **AEGIS-Tunnel** |
|------|-----------|---------|-----------------|
| 代码量 | ~4K 行 | ~100K+ 行 | **~2K 行** |
| 加密算法 | ChaCha20-Poly1305 | AES-GCM | **AEGIS-128** |
| ARM NEON | ✅ | ✅ | **✅ Plain NEON** |
| 独立发布 | 否 | 否 | **✅ 完全独立** |

## 构建

### 依赖

- CMake >= 3.16
- GCC >= 9.0 (或 Clang >= 10.0)
- OpenSSL (libssl-dev) — 用于 SHA256 密钥派生
- ARM NEON 需要 `aarch64-linux-gnu-gcc`（交叉编译）或 ARM64 原生编译

### 标准构建（x86_64）

```bash
# 安装依赖
sudo apt install cmake libssl-dev

# 构建
cd aegis-tunnel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 调试构建（含 Sanitizer）

```bash
cmake -B build -DENABLE_ASAN=ON -DENABLE_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### ARM 交叉编译（启用 NEON）

```bash
# 安装 ARM 交叉编译器
sudo apt install gcc-aarch64-linux-gnu

# 交叉编译
cmake -B build-arm \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DWITH_NEON=ON \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm
```

## 使用

### 生成 PSK

```bash
# 推荐方式：生成 16 字节随机密钥存入文件（chmod 400 保护）
dd if=/dev/urandom bs=16 count=1 of=/etc/aegis/psk.key
chmod 400 /etc/aegis/psk.key

# 或使用 hex 字符串（注意：ps aux 中可见！仅用于测试）
xxd -p -c 32 /dev/urandom | head -1
```

### 服务器模式

```bash
# 推荐：使用 PSK 文件
./build/aegis-tunnel -l 9000 -r 127.0.0.1:8080 -f /etc/aegis/psk.key

# 可选参数
./build/aegis-tunnel -l 9000 -r 127.0.0.1:8080 -f /etc/aegis/psk.key \
    -t 10 \    # 握手超时 10 秒（默认 5）
    -c 64 \    # 最大 64 个并发连接（默认 32）
    -K 30      # 30 秒心跳保活
```

### 客户端模式

```bash
./build/aegis-tunnel -l 9000 -r server.example.com:9000 \
    -f /etc/aegis/psk.key -m client
```

### 完整命令行

```
选项：
  -l <port>       本地监听端口（必需）
  -r <host:port>  远程目标地址（必需）
  -k <hex>        PSK hex 字符串（测试用，进程列表中可见）
  -f <file>       PSK 文件路径（生产推荐，chmod 400）
  -m <mode>       server（默认）或 client
  -t <sec>        握手超时秒数（默认 5）
  -c <max>        最大并发连接数（默认 32）
  -K <sec>        心跳保活间隔秒数（默认 0 = 禁用）
  -h              显示帮助
```

## 协议

### 帧格式

```
 0      1      2-3         4...(N+3)      (N+4)...(N+19)
+------+------+--------+--------//----+--------//--------+
| type | flags| length |   payload     |    tag (16 B)    |
|  1   |  1   |  2 BE  |  0..65535 B   |                  |
+------+------+--------+--------//----+--------//--------+
```

- 帧头 (4 字节) 作为 AEGIS-128 关联数据（AD）
- 负载加密，16 字节标签认证全体

### 帧类型

| 类型 | 值 | 说明 |
|------|-----|------|
| HANDSHAKE | 0x01 | 握手帧 |
| DATA | 0x02 | 加密数据帧 |
| KEEPALIVE | 0x03 | 心跳保活 |
| CLOSE | 0x04 | 连接关闭 |

### 握手流程

```
客户端                                    服务器
  |                                          |
  |── HANDSHAKE(加密: nonce_c + ts_c) ──────▶|
  |                                          | 验证 PSK + 时间戳
  |◀─ HANDSHAKE(加密: nonce_s + ts_s) ───────│
  |                                          |
  |── DATA(加密流量) ────────────────────────▶|
  |◀─ DATA(加密流量) ────────────────────────│
```

密钥派生：`session_secret = SHA256(PSK || nonce_c || nonce_s)`

## 测试

```bash
# 运行 AEGIS-128 算法测试
./build/test-aegis

# 运行隧道集成测试
./build/test-tunnel

# 运行性能基准测试
./build/bench-aegis
```

## 性能

AEGIS-128 纯 C 实现在现代 x86_64 CPU 上的吞吐量（通过 `bench-aegis` 测量）。

ARM 平台上的 NEON 加速预期（来自设计文档）：

| 平台 | 纯 C | NEON (AES 指令) | NEON (Plain tbl) |
|------|------|-----------------|-------------------|
| 树莓派 3 (Cortex-A53) | ~180 MB/s | N/A | **~350 MB/s** |
| 树莓派 4 (Cortex-A72) | ~200 MB/s | **~800 MB/s** | ~400 MB/s |
| 树莓派 5 (Cortex-A76) | ~250 MB/s | **~1200 MB/s** | ~500 MB/s |
| Apple M2 | ~300 MB/s | **~2500 MB/s** | ~600 MB/s |

## 安全

- 加密：AEGIS-128，128 位安全性
- 认证：128 位标签，2^-128 伪造概率
- 防重放：握手时间戳 ±60s 窗口 + 每方向 nonce 计数器
- 时序安全：标签比较使用常量时间算法
- 内存安全：敏感数据（密钥、nonce）使用后立即清零

**注意**：此项目使用静态 PSK，不提供前向安全性。每个连接使用独立的 nonce 交换来派生会话密钥。

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

## 参考

- [AEGIS 规范 (CAESAR 竞赛提交)](https://competitions.cr.yp.to/round3/aegisv11.pdf)
- [IETF CFRG AEGIS 草案](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead)
- [NEON 编程指南](https://developer.arm.com/architectures/instruction-sets/intrinsics/)
