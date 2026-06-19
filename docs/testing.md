# AEGIS-Tunnel 完整测试与使用指南

## 目录

1. [编译与单元测试](#1-编译与单元测试)
2. [代理模式：两台机器建立加密 TCP 隧道](#2-代理模式两台机器建立加密-tcp-隧道)
3. [TUN VPN 模式：四阶段工作流](#3-tun-vpn-模式四阶段工作流)
4. [传输优化：多路径与 UDP 模式](#4-传输优化多路径与-udp-模式)
5. [SOCKS5 代理模式](#5-socks5-代理模式)
6. [传统命令行方式（兼容旧版）](#6-传统命令行方式兼容旧版)
7. [多客户端管理](#7-多客户端管理)
8. [抓包验证加密](#8-抓包验证加密)
9. [故障排查](#9-故障排查)

---

## 1. 编译与单元测试

```bash
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
make
```

**预期输出**: 7 行 `→ xxx built`

```bash
# 运行全部自动化测试（23 项）
./test-aegis       # AEGIS-128 加密算法: 13/13
./test-tunnel      # 帧协议 + 非对称握手: 8/8
./e2e-test         # 端到端握手 + 加解密: 2/2
./bench-aegis      # 性能基准（可选）

# 一键测试
make test
```

---

## 2. 代理模式：两台机器建立加密 TCP 隧道

### 场景

```
树莓派 (客户端)                    服务器 (x86)
10.0.0.2                            192.168.1.100
    │                                    │
    │  把本地 9000 端口的 TCP 流量        │
    │  加密后转发到服务器的 8080 端口     │
    │                                    │
    └──────── 加密 TCP ────────────────▶  │
                                         │
                                    解密 → 127.0.0.1:8080
```

### 服务端操作

```bash
python3 -m http.server 8080 &
./aegis-tunnel keygen
# 将输出的公钥发给客户端

./aegis-tunnel peer add pi <客户端的64位hex公钥>
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server
```

### 客户端（树莓派）操作

```bash
make
./aegis-tunnel keygen
# 将输出的公钥发给服务端

./aegis-tunnel peer add server <服务端的64位hex公钥>
./aegis-tunnel -l 9000 -r 192.168.1.100:9000 -m client
```

### 测试

```bash
curl http://127.0.0.1:9000/
# 预期: 看到服务器上 python http.server 的目录列表
```

### 代理模式参数

| 参数 | 服务端 | 客户端 | 说明 |
|------|--------|--------|------|
| `-l <port>` | 监听端口 | 监听端口 | 本地端口 |
| `-r <host:port>` | 解密后转发目标 | 服务端地址 | 远程地址 |
| `-m <mode>` | `server` | `client` | 运行模式 |
| `-K <sec>` | 可选 | 可选 | Keepalive 间隔（秒） |
| `-t <sec>` | 可选 | 可选 | 握手超时（秒，默认5） |
| `-x <max>` | 可选 | — | 最大并发连接数（默认32） |

---

## 3. TUN VPN 模式：四阶段工作流

### 场景

```
树莓派 (客户端)                    服务器 (x86)
tun0: 10.0.0.2                       tun0: 10.0.0.1
    │                                    │
    │  IP 包通过加密隧道传输              │  NAT 转发到 eth0 → 互联网
    │                                    │
    └──────── 加密 TCP ────────────────▶  │
                                         │
                                    解密 → TUN → NAT → eth0
```

TUN 模式在 IP 层工作：创建虚拟网卡，所有命中路由规则的 IP 包经过加密隧道发送到对端。

### 阶段 1：keygen — 生成密钥 + 基础配置

```bash
# 服务器和客户端都执行
./aegis-tunnel keygen
```

产出：
- `~/.aegis-tunnel/private.key` — 私钥（二进制，权限 600）
- `~/.aegis-tunnel/public.key` — 公钥（hex 文本）
- `aegis.conf` — 基础配置文件

### 阶段 2：peer add — 交换公钥

```bash
# 服务器上添加客户端的公钥
./aegis-tunnel peer add pi <客户端64位hex公钥>

# 客户端上添加服务器的公钥
./aegis-tunnel peer add server <服务器64位hex公钥>
```

验证：
```bash
./aegis-tunnel peer list
./aegis-tunnel status
```

### 阶段 3：create tun — 生成 TUN 配置

```bash
# 服务端
./aegis-tunnel create tun -server
# 输出 aegis-server.conf

# 客户端
./aegis-tunnel create tun -client
# 输出 aegis-client.conf
```

**客户端按需编辑 `aegis-client.conf`**：
```ini
[Peer]
Endpoint = 1.2.3.4:9000        # ← 改为服务器真实地址
AllowedIPs = 0.0.0.0/0          # 全隧道；或 10.0.0.0/24 分流
```

### 阶段 4：start tun — 启动 VPN

```bash
# 服务端
sudo ./aegis-tunnel start tun -server

# 客户端
sudo ./aegis-tunnel start tun -client
```

### 验证

```bash
# ping 服务端 TUN IP（纯隧道路径）
ping 10.0.0.1

# 查看 TUN 网卡
ip addr show tun0

# 查看路由表
ip route | grep tun0

# 全隧道校验
curl ifconfig.me  # 应显示服务器公网 IP
```

### 停止

```bash
# Ctrl+C 优雅关闭（自动执行 PostDown + 清理路由）
# 或手动清理
sudo ./aegis-tunnel tun down
```

### TUN 配置速查

| 配置键 | 位置 | 服务端 | 客户端 | 说明 |
|--------|------|--------|--------|------|
| `Address` | `[Interface]` | `10.0.0.1/24` | `10.0.0.2/24` | TUN 虚拟 IP |
| `ListenPort` | `[Interface]` | `9000` | — | 监听端口 |
| `PostUp` | `[Interface]` | 可选 | 可选 | 启动后脚本（`%i` = 网卡名） |
| `PostDown` | `[Interface]` | 可选 | 可选 | 关闭前脚本 |
| `Endpoint` | `[Peer]` | 可选 | **必需** | 服务器真实地址 |
| `AllowedIPs` | `[Peer]` | `10.0.0.0/24` | `0.0.0.0/0` | 路由网段（逗号分隔） |
| `PersistentKeepalive` | `[Peer]` | — | `25` | 保活间隔（秒） |
| `NATInterface` | `[Tunnel]` | `eth0` | — | NAT 出站网卡 |

---

## 4. 传输优化：多路径与 UDP 模式

TUN 模式默认使用单条 TCP 连接传输所有流量，存在两个固有问题：
- **队头阻塞**：一个 TCP 重传会阻塞所有后续帧
- **TCP-over-TCP**：内外层 TCP 拥塞控制嵌套，性能不可预测

提供两种优化方案：

### 4.1 TCP 多路径 (`-M`)

客户端与服务端之间建立 N 条并行 TCP 连接（默认 4），按五元组哈希分发：

```bash
# 服务端
sudo ./aegis-tunnel start tun -server

# 客户端（4 路并行）
sudo ./aegis-tunnel start tun -client -r 服务器IP:9000 -M 4
```

```
TUN 设备
   │
   ▼
父进程 poll()
   │
   ├─ 哈希 → sp[0] → 子进程0 → TCP连接1 → 服务端
   ├─ 哈希 → sp[1] → 子进程1 → TCP连接2 → 服务端
   ├─ 哈希 → sp[2] → 子进程2 → TCP连接3 → 服务端
   └─ 哈希 → sp[3] → 子进程3 → TCP连接4 → 服务端
```

- 同一条流的包始终走同一连接（流亲和性）
- 某连接重传时其他连接不受影响
- 服务端自动轮询分发回程流量

### 4.2 UDP 传输模式 (`-U`)

用 UDP 数据报替代 TCP 流，彻底消除 TCP-over-TCP 问题：

```bash
# 服务端
sudo ./aegis-tunnel start tun -server -U

# 客户端
sudo ./aegis-tunnel start tun -client -U -r 服务器IP:9000
```

- 每个 IP 包 → 一个 UDP 数据报 → 一个 AEGIS 帧
- 无应用层重传（内层 TCP 自行负责）
- 握手通过 UDP 完成（复用现有 3-DH 协议）
- 保活帧维持 NAT 映射

### 4.3 组合使用

```bash
# UDP 多路传输
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client -r 服务器:9000 -U -M 4
```

### 4.4 选型建议

| 场景 | 推荐方案 | 参数 |
|------|---------|------|
| 普通浏览 | 默认 TCP | 无需额外参数 |
| 大文件下载 | TCP 多路径 | `-M 4` |
| 游戏/语音 | UDP 模式 | `-U` |
| 最高吞吐 | UDP 多路 | `-U -M 4` |

---

## 5. SOCKS5 代理模式

### 场景

不需要 root 权限的应用层代理模式。适合浏览器/curl 按需走隧道。

```bash
# 服务端
./aegis-tunnel socks5 -server -l 9000

# 客户端
./aegis-tunnel socks5 -client -l 1080 -r 服务器IP:9000

# 使用
curl --socks5 127.0.0.1:1080 https://www.baidu.com
# 浏览器设置 SOCKS5 代理: 127.0.0.1:1080
```

### 工作原理

```
浏览器                                AEGIS 服务端
  │                                       │
  │ SOCKS5 CONNECT baidu.com:443          │
  ▼                                       │
客户端 socks5_accept() → 获取目标地址       │
  │                                       │
  │ AEGIS 握手 + 发送 CONNECT_REQUEST     │
  │ ──────── 加密 TCP ────────────────▶   │
  │                                       │ 收到目标地址 → connect(baidu.com:443)
  │◀─────── 加密 TCP ─────────────────   │
  ▼                                       ▼
隧道转发                                隧道转发
```

---

## 6. 传统命令行方式（兼容旧版）

不依赖配置文件，适合快速测试：

```bash
# 服务端
sudo ./aegis-tunnel -T 10.0.0.1/24 -W eth0 -m server -Q <客户端公钥hex>

# 客户端（分流）
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 10.0.0.0/24 -m client -r 服务器IP:9000 -Q <服务端公钥hex>

# 客户端（全隧道）
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client -r 服务器IP:9000 -Q <服务端公钥hex>
```

### 命令行参数速查

| 参数 | 说明 | 示例 |
|------|------|------|
| `-l <port>` | 本地监听端口 | `-l 9000` |
| `-r <host:port>` | 远程目标地址 | `-r 1.2.3.4:9000` |
| `-m <mode>` | 运行模式 | `-m server` 或 `-m client` |
| `-T <ip/prefix>` | TUN VPN CIDR | `-T 10.0.0.1/24` |
| `-R <network>` | TUN 路由 | `-R 10.0.0.0/24` |
| `-W <iface>` | WAN 网卡 | `-W eth0` |
| `-P <file>` | 私钥文件 | `-P /path/to/private.key` |
| `-Q <hex\|file>` | 对端公钥 | `-Q a1b2...` 或 `-Q peer.pub` |
| `-c <file>` | 配置文件路径 | `-c aegis.conf` |
| `-K <sec>` | Keepalive 间隔 | `-K 30` |
| `-t <sec>` | 握手超时 | `-t 10` |
| `-x <max>` | 最大连接数 | `-x 64` |
| `-v` | 详细日志 | — |

---

## 7. 多客户端管理

TUN 服务端支持多个客户端同时连接。

### 配置

```bash
./aegis-tunnel peer add client-a <公钥A>
./aegis-tunnel peer add client-b <公钥B>
```

**重要：每个客户端的 `Address` 必须不同**：
```ini
# client-a
Address = 10.0.0.2/24

# client-b
Address = 10.0.0.3/24
```

### 安全机制

- per-IP 握手速率限制（5次/60s）
- 握手时间戳重放检测
- 每 120 秒自动密钥轮换

---

## 8. 抓包验证加密

### TUN 模式抓包

```bash
# 服务器 TUN 接口抓明文（解密后进入网卡的数据）
sudo tcpdump -i tun0 -n -c 20

# 服务器物理网卡抓密文（隧道流量）
sudo tcpdump -i eth0 -n port 9000 -X -c 5
```

**预期结果**：
- `tun0` 上看到正常 IP 包（ping、TCP 等）
- `eth0` 端口 9000 看到加密乱码，无法识别原始内容

### 加密帧格式

```
0x0000:  0200 0010 a3f2 7c1d e2b5 9f4a ...   ← 帧类型 0x02 (DATA)
0x0010:  c71e d308 6bd4 f9e3 7284 1acf ...   ← 加密负载（AEGIS-128 密文）
0x0020:  5e2b 941f                           ← 认证标签（16 字节）
```

---

## 9. 故障排查

### 通用问题

| 现象 | 原因 | 解决 |
|------|------|------|
| `make` 只生成一个文件 | `.o` 缓存冲突 | `make clean && make` |
| `cannot find -lssl` | 缺少 OpenSSL 开发库 | `sudo apt install libssl-dev` |
| `handshake failed` | 对端公钥不匹配 | 检查双方公钥，重新 `peer add` |
| `No peer key found` | 未添加对端公钥 | `./aegis-tunnel peer add <name> <hex>` |
| `bind: Address already in use` | 端口被占用 | `ss -tlnp \| grep 9000` 找到并 kill |

### TUN 模式专用

| 现象 | 原因 | 解决 |
|------|------|------|
| `TUNSETIFF: Operation not permitted` | 无 root 权限 | `sudo` |
| `/dev/net/tun: No such file` | TUN 模块未加载 | `sudo modprobe tun` |
| ping 不通 10.0.0.1 | 路由未生效或 IP 冲突 | `ip route` 检查，确认双方在同一子网 |
| 全隧道后无法上网 | fwmark 规则未生效 | `ip rule list` 检查 |
| NAT 不工作 | iptables 规则未添加 | `sudo iptables -t nat -L POSTROUTING` |
| 隧道自身连接也走了 TUN | fwmark 未设置 | 检查 `ip rule` 和 SO_MARK |
| ping 外网丢包但 ping 10.0.0.1 正常 | 目标网站限制 ICMP | 用 `curl` TCP 测试验证 |

### 调试技巧

```bash
# 详细日志
./aegis-tunnel -v ...

# 验证密钥
./aegis-tunnel status

# 检查 TUN
ip addr show tun0
ip link show tun0

# 检查路由
ip route show table main | grep tun0
ip rule list

# 检查防火墙
sudo iptables -t nat -L POSTROUTING -v
sudo iptables -L FORWARD -v

# 手动清理
sudo ip link del tun0
sudo ip rule del fwmark 51820 table main
sudo iptables -t nat -F POSTROUTING
sudo iptables -F FORWARD

# 强制纯 C 加密后端（排查加密问题）
AEGIS_PURE_C=1 sudo -E ./aegis-tunnel start tun -server
```
