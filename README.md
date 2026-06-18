# AEGIS-Tunnel

基于 **AEGIS-128** 认证加密 + **X25519 ECDH** 的轻量级安全隧道，支持 TUN VPN 和 TCP 代理双模式，自动选择最优加密后端（x86 AES-NI / ARM Crypto / Pure C）。

## 概述

AEGIS-Tunnel 是一个极简的加密隧道工具，提供：

- **TUN VPN 模式**：WireGuard 风格的四阶段工作流（keygen → peer add → create tun → start tun）
- **代理模式**：加密 TCP 隧道转发（类似 Stunnel/SSH -L）
- **非对称握手**：基于 X25519 的 3-DH 密钥交换，支持多 Peer 管理
- **自动加密后端选择**：x86 AES-NI（~92x 加速）> ARM Crypto > ARM NEON > Pure C

## 特性

- **AEGIS-128 AEAD**：CAESAR 竞赛冠军算法，IETF CFRG 标准化中
- **X25519 非对称握手**：3-DH 密钥交换 + 时间戳防重放，支持多 Peer
- **TUN 虚拟网卡**：L3 VPN，支持全隧道 / 分流隧道 / 多网段路由
- **fwmark 策略路由**：自动标记隧道自身的 TCP 连接，防止路由环路
- **多平台加速**：x86_64 AES-NI / aarch64 ARM Crypto / ARM NEON / Pure C
- **WireGuard 风格配置**：INI 文件管理，`peer add/delete/list` 子命令
- **自动清理**：Ctrl+C 时自动清除路由规则和 TUN 设备
- **~1500 行 C99 代码**（主程序 + 模式 + 配置管理），易于审计和定制

## 项目结构

```
src/
├── main.c              # 入口：参数解析 + 模式分发（519 行）
├── main.h              # 全局变量和函数声明
├── config_mgmt.c/h     # 配置管理：keygen / peer add/delete / create tun
├── mode_common.c/h     # 共享模式代码：多 Peer 握手
├── mode_psk.c          # 代理模式（TCP 隧道）
├── mode_tun.c          # TUN VPN 模式
├── crypto/             # AEGIS-128 加密算法
│   ├── aegis.c/h       # 核心实现 + 运行时后端选择
│   ├── x86/            # x86 AES-NI 加速
│   └── neon/           # ARM Crypto + NEON 加速
├── protocol/           # 网络协议
│   ├── handshake.c/h   # X25519 3-DH 握手 + 密钥确认 + rekey
│   ├── ecdh.c/h        # X25519 密钥交换（OpenSSL EVP）
│   ├── frame_reader.c/h # TCP 流帧解析器
│   └── keyfile.c/h     # 密钥文件 I/O
├── tunnel/             # 隧道引擎
│   ├── tunnel.c/h      # poll() 事件循环 + 帧加解密
│   ├── tun.c/h         # TUN 设备管理 + 路由 + iptables
│   └── threadpool.c/h  # 线程池（可选，默认 fork）
├── proxy/              # SOCKS5 代理（可选）
│   └── socks5.c/h
└── util/               # 工具库
    ├── util.c/h        # hex_dump / random_bytes / secure_memzero
    ├── iniconfig.c/h   # WireGuard 风格 INI 解析器
    ├── config.c/h      # 旧版 key=value 兼容解析器
    └── log.c/h         # 日志模块
```

## 快速开始

### 依赖

- GCC >= 9.0（或 Clang >= 10.0）
- OpenSSL >= 1.1.1（libssl-dev，用于 X25519 + SHA256）
- Linux（TUN 模式依赖 `/dev/net/tun`、`ip` 命令、`iptables`）

### 编译

```bash
# 快速编译（Makefile）
make

# 或使用 CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# ARM 交叉编译（树莓派等）
make                    # Makefile 自动检测 aarch64
```

### TUN VPN 模式（四阶段工作流）

```bash
# 阶段 1：生成密钥对 + 基础配置
./aegis-tunnel keygen

# 阶段 2：交换公钥（双方执行）
./aegis-tunnel peer add <对端名称> <对端64位hex公钥>

# 阶段 3：生成 TUN 配置文件
./aegis-tunnel create tun -server    # 服务端
./aegis-tunnel create tun -client    # 客户端

# 阶段 4：启动 VPN（需要 root）
sudo ./aegis-tunnel start tun -server
sudo ./aegis-tunnel start tun -client
```

**客户端** `aegis-client.conf` 关键配置：

```ini
[Peer]
Endpoint = 服务器IP:9000    # ← 修改为服务器真实地址
AllowedIPs = 0.0.0.0/0      # 全隧道；或 10.0.0.0/24 分流
```

### 代理模式（TCP 加密隧道，兼容旧版）

```bash
# 服务端：解密后转发到 127.0.0.1:8080
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server

# 客户端：监听本地 9000，加密后发到服务端
./aegis-tunnel -l 9000 -r 服务器IP:9000 -m client
```

### 管理命令

```bash
./aegis-tunnel status          # 查看密钥和 Peer 状态
./aegis-tunnel peer list       # 列出已知 Peer
./aegis-tunnel peer delete <名称>  # 删除 Peer
sudo ./aegis-tunnel tun down   # 手动清理 TUN 设备和路由
```

### 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-l <port>` | 本地监听端口 | `-l 9000` |
| `-r <host:port>` | 远程目标地址 | `-r 1.2.3.4:9000` |
| `-m <mode>` | 运行模式 | `-m server` 或 `-m client` |
| `-T <ip/prefix>` | TUN VPN CIDR | `-T 10.0.0.1/24` |
| `-R <network>` | TUN 路由 (AllowedIPs) | `-R 10.0.0.0/24` |
| `-W <iface>` | WAN 网卡（NAT 用） | `-W eth0` |
| `-P <file>` | 私钥文件路径 | `-P /path/to/private.key` |
| `-Q <hex\|file>` | 对端公钥 | `-Q a1b2...` 或 `-Q peer.pub` |
| `-c <file>` | 配置文件路径 | `-c aegis.conf` |
| `-K <sec>` | Keepalive 间隔 | `-K 30` |
| `-t <sec>` | 握手超时 | `-t 10` |
| `-x <max>` | 最大连接数 | `-x 64` |
| `-v` | 详细日志 | — |
| `-h` | 显示帮助 | — |

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
- 16 字节认证标签覆盖帧头 + 密文
- Nonce = 64 位小端序计数器 || 8 字节零

### 非对称握手流程（X25519 3-DH）

```
客户端                                         服务器
  |                                               |
  |── handshake_init(eph_pub_c, ts_c) ──────────▶|
  |     AEGIS 加密，密钥 = SHA256(ee||es||"init") |
  |                                               | 验证时间戳，尝试所有已知 Peer 公钥
  |◀─ handshake_resp(eph_pub_s, ts_s) ──────────│
  |     AEGIS 加密，密钥 = SHA256(shared||"resp") |
  |                                               |
  |◀══ KEY_CONFIRM ─══════════════════════════════│ (服务端先发)
  |══▶ KEY_CONFIRM ─══════════════════════════════▶| (客户端验证)
  |                                               |
  |══▶ DATA (加密流量) ─══════════════════════════▶|
  |◀══ DATA (加密流量) ─═══════════════════════════│
```

共享密钥：`SHA256(ee || es || se || "shared")`，其中：
- `ee` = 临时私钥 × 对端临时公钥
- `es` = 自身私钥 × 对端临时公钥
- `se` = 临时私钥 × 对端静态公钥

## 测试

```bash
make test           # 一键运行所有测试

# 或逐个运行
./test-aegis        # AEGIS-128 算法：13 项测试
./test-tunnel       # 帧协议 + 非对称握手：8 项测试
./e2e-test          # 端到端握手 + 加解密：2 项测试
./bench-aegis       # 性能基准测试
```

## 性能

| 平台 | Pure C | x86 AES-NI | ARM Crypto | ARM NEON |
|------|--------|-----------|------------|----------|
| x86_64 | ~400 MB/s | **~3,700 MB/s** | — | — |
| 树莓派 3 (A53) | ~180 MB/s | — | — | ~350 MB/s |
| 树莓派 4 (A72) | ~200 MB/s | — | ~800 MB/s | ~400 MB/s |
| 树莓派 5 (A76) | ~250 MB/s | — | ~1,200 MB/s | ~500 MB/s |
| Apple M2 | ~300 MB/s | — | ~2,500 MB/s | ~600 MB/s |

## 安全

- **加密**：AEGIS-128，128 位安全性
- **密钥交换**：X25519 3-DH，每个会话独立临时密钥（前向安全性）
- **认证**：128 位标签，2^-128 伪造概率
- **防重放**：握手时间戳 ±60s 窗口 + 每方向 nonce 计数器单调递增
- **时序安全**：标签比较使用常量时间算法
- **内存安全**：敏感数据（密钥、nonce、共享密钥）使用后立即 `secure_memzero()`

## 详细文档

- [协议规范](docs/protocol.md)
- [测试与使用指南](docs/testing.md)
- [已知问题与改进计划](docs/known-issues.md)

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

## 参考

- [AEGIS 规范 (CAESAR 竞赛提交)](https://competitions.cr.yp.to/round3/aegisv11.pdf)
- [IETF CFRG AEGIS 草案](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead)
- [WireGuard 协议设计](https://www.wireguard.com/papers/wireguard.pdf)
