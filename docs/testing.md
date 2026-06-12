# AEGIS-Tunnel 完整测试与使用指南

## 目录

1. [编译与单元测试](#1-编译与单元测试)
2. [代理模式：两台机器建立加密 TCP 隧道](#2-代理模式两台机器建立加密-tcp-隧道)
3. [TUN VPN 模式：四阶段工作流](#3-tun-vpn-模式四阶段工作流)
4. [传统命令行方式（兼容旧版）](#4-传统命令行方式兼容旧版)
5. [多客户端管理](#5-多客户端管理)
6. [抓包验证加密](#6-抓包验证加密)
7. [故障排查](#7-故障排查)

---

## 1. 编译与单元测试

```bash
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
make
```

**预期输出**：6 行 `→ xxx built`

```bash
# 运行全部自动化测试（22 项）
./test-aegis       # AEGIS-128 加密算法: 12/12
./test-tunnel      # 帧协议 + 非对称握手: 8/8
./e2e-test         # 端到端握手: 2/2
./bench-aegis      # 性能基准（可选）
```

---

## 2. 代理模式：两台机器建立加密 TCP 隧道

### 场景

```
树莓派 (客户端)                    服务器 (x86)
10.0.0.2                           192.168.1.100
    │                                  │
    │  把本地 9000 端口的 TCP 流量       │
    │  加密后转发到服务器的 8080 端口    │
    │                                  │
    └──────── 加密 TCP ──────────────▶  │
                                       │
                                  解密 → 127.0.0.1:8080
```

代理模式在 TCP 层工作：客户端监听本地端口，将收到的 TCP 连接加密后中继到服务端，服务端解密后转发到目标地址。

### 第一步：服务端操作

```bash
# 1. 启动一个 Web 服务（模拟你的业务后端）
python3 -m http.server 8080 &

# 2. 生成密钥对
./aegis-tunnel keygen
# 输出：
#   Public key (send to peer):
#     a1b2c3d4e5f6...（复制这行，发给树莓派）
#   Config: aegis.conf

# 3. 添加树莓派的公钥（等树莓派生成后发给你）
./aegis-tunnel peer add pi <树莓派的64位hex公钥>

# 4. 启动代理服务端
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server
```

### 第二步：树莓派（客户端）操作

```bash
# 1. 编译
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel && make

# 2. 生成密钥对
./aegis-tunnel keygen
# 输出：
#   Public key (send to peer):
#       f6e5d4c3b2a1...（复制这行，发给服务器）

# 3. 添加服务器的公钥
./aegis-tunnel peer add server <服务器的64位hex公钥>

# 4. 启动代理客户端
./aegis-tunnel -l 9000 -r 192.168.1.100:9000 -m client
```

### 第三步：测试代理隧道

```bash
# 在树莓派上，访问本地 9000 端口
# 流量会自动加密后转发到服务器的 8080 端口
curl http://127.0.0.1:9000/
# 预期：看到服务器上 python http.server 的目录列表
```

### 代理模式配置参数

| 参数 | 服务端 | 客户端 | 说明 |
|------|--------|--------|------|
| `-l <port>` | 监听端口 | 监听端口 | 本地监听端口 |
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
tun0: 10.0.0.2                      tun0: 10.0.0.1
    │                                  │
    │  IP 包通过加密隧道传输            │  NAT 转发到 eth0 → 互联网
    │                                  │
    └──────── 加密 TCP ──────────────▶  │
                                       │
                                  解密 → TUN → NAT → eth0
```

TUN 模式在 IP 层工作：创建虚拟网卡，所有命中路由规则的 IP 包都经过加密隧道发送到对端。

### 阶段 1：keygen — 生成密钥 + 基础配置

```bash
# 在服务器和树莓派上都执行
./aegis-tunnel keygen
```

**生成产物**：
- `~/.aegis-tunnel/private.key` — 私钥（二进制，权限 400）
- `~/.aegis-tunnel/public.key` — 公钥（hex 文本，权限 644）
- `aegis.conf` — 基础配置文件（当前目录）

**aegis.conf 内容**：
```ini
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...    ← 本机的公钥
Port = 9000
Mode = server

[Tunnel]
Keepalive = 30
NATInterface = eth0
```

**输出示例**：
```
Public key (send to peer):
  cc65dd6af87f0b819f6ac83f1bbc117a33fe217259d23feac2ed40e5326d0707

Config: aegis.conf

Next: get peer's public key, then:
  aegis-tunnel peer add <name> <peer-hex-key>
```

### 阶段 2：peer add — 交换公钥

```bash
# 服务器上：添加树莓派的公钥
./aegis-tunnel peer add pi <树莓派的64位hex公钥>

# 树莓派上：添加服务器的公钥
./aegis-tunnel peer add server <服务器的64位hex公钥>
```

**aegis.conf 更新后**（服务器侧示例）：
```ini
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...    ← 本机公钥

[Tunnel]
Keepalive = 30
NATInterface = eth0

[Peer]
PublicKey = f6e5d4c3b2a1...    ← 树莓派的公钥
Endpoint = pi                   ← 对端标识
```

**验证**：
```bash
./aegis-tunnel peer list
# 输出:
#   Known peers:
#     pi

./aegis-tunnel status
# 输出:
#   Key storage: /home/user/.aegis-tunnel
#     Private key: .../private.key (exists)
#     Public key:  .../public.key (exists)
#   Known peers:
#     pi
```

### 阶段 3：create tun — 生成 TUN 配置文件

#### 3a. 服务端

```bash
./aegis-tunnel create tun -server
# 输出:
#   TUN server config written to aegis-server.conf
#
#   Review and edit aegis-server.conf if needed, then:
#     sudo ./aegis-tunnel start tun -server
```

**生成的 aegis-server.conf**：
```ini
# AEGIS-Tunnel TUN server config (generated from aegis.conf)

[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...
Mode = server
Address = 10.0.0.1/24           ← TUN 虚拟网卡 IP
ListenPort = 9000                ← 监听端口（独立于 Port）
# PostUp = iptables ...          ← 可选：取消注释以启用自动 NAT 规则
# PostDown = iptables ...

[Peer]
PublicKey = f6e5d4c3b2a1...     ← 客户端公钥
AllowedIPs = 10.0.0.0/24        ← 允许对端访问的网段（可逗号分隔多个）
# Endpoint = pi

[Tunnel]
Keepalive = 30
NATInterface = eth0              ← 出站网卡（NAT 用）
Timeout = 10
MaxConnections = 64
```

**按需修改**：
```bash
vim aegis-server.conf
```
- 如果 TUN 子网不是 `10.0.0.0/24`，修改 `Address` 和 `AllowedIPs`
- 如需自动配置 NAT，取消 `PostUp` / `PostDown` 的注释
- 如果外网网卡不是 `eth0`，修改 `NATInterface`

#### 3b. 客户端

```bash
./aegis-tunnel create tun -client
# 输出:
#   TUN client config written to aegis-client.conf
#
#   Review and edit aegis-client.conf if needed, then:
#     sudo ./aegis-tunnel start tun -client
```

**生成的 aegis-client.conf**：
```ini
# AEGIS-Tunnel TUN client config (generated from aegis.conf)

[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = f6e5d4c3b2a1...
Mode = client
Address = 10.0.0.2/24           ← 客户端 TUN IP

[Peer]
PublicKey = cc65dd6af87f...     ← 服务器公钥
Endpoint = server:9000           ← 服务器的真实地址:端口
AllowedIPs = 0.0.0.0/0          ← 全隧道（所有流量走 VPN）
PersistentKeepalive = 30

[Tunnel]
Keepalive = 30
NATInterface = eth0
Timeout = 10
MaxConnections = 64
```

**按需修改**：
```bash
vim aegis-client.conf
```
- **`Endpoint`**：改为服务器的真实 IP 或域名 + 端口（如 `1.2.3.4:9000`）
- **`AllowedIPs`**：
  - `0.0.0.0/0` → 全隧道：所有流量走 VPN
  - `10.0.0.0/24` → 分流：只访问 VPN 内网的流量走隧道
  - `10.0.0.0/24,192.168.1.0/24` → 多网段分流

### 阶段 4：start tun — 启动 VPN

#### 4a. 启动服务端

```bash
sudo ./aegis-tunnel start tun -server
```

**自动执行的操作**：
1. 创建 TUN 虚拟网卡 `tun0`
2. 配置 IP 地址 `10.0.0.1/24`
3. 启用网卡
4. 添加路由 `10.0.0.0/24 dev tun0`
5. 启用 IP 转发
6. 设置 fwmark 策略路由（防止路由环路）
7. 为每个 AllowedIPs 网段添加 NAT MASQUERADE
8. 添加 FORWARD 防火墙规则
9. 执行 PostUp 脚本（如果配置了）
10. 监听加密连接（默认 9000 端口）

**预期输出**：
```
[tun] created device: tun0 (fd=6)
[tun] tun0: 10.0.0.1/24
[tun] IP forwarding: enabled
[tun] fwmark 51820: policy routing set
[tun] NAT: 10.0.0.0/24 → eth0 (MASQUERADE)
[tun] FORWARD rules: tun0 → ACCEPT
[INFO ] [tun-server] tun0 (10.0.0.1/255.255.255.0) :9000 route=10.0.0.0/24 peers=1
```

#### 4b. 启动客户端

```bash
sudo ./aegis-tunnel start tun -client
```

**自动执行的操作**：
1. 创建 TUN 虚拟网卡 `tun0`
2. 配置 IP 地址 `10.0.0.2/24`
3. 启用网卡
4. 为每个 AllowedIPs 网段添加路由到 tun0
5. 设置 fwmark 策略路由
6. 执行 PostUp 脚本（如果配置了）
7. 连接到服务器并开始加密通信

**预期输出**：
```
[tun] created device: tun0 (fd=6)
[tun] tun0: 10.0.0.2/24
[tun] fwmark 51820: policy routing set
[tun] full tunnel: 0.0.0.0/0 → tun0
[INFO ] [tun-client] tun0 (10.0.0.2/255.255.255.0) → server.com:9000 route=0.0.0.0/0 (auto-reconnect)
```

### TUN 模式验证

```bash
# 1. 在客户端 ping 服务端的 TUN IP
ping 10.0.0.1
# 预期：有响应（ICMP 包通过加密隧道传输）

# 2. 查看 TUN 网卡状态
ip addr show tun0
# 预期：显示配置的 IP 地址

# 3. 查看路由表
ip route | grep tun0
# 预期：显示通过 tun0 的路由条目

# 4. 在服务端抓取 TUN 流量
sudo tcpdump -i tun0 -n -c 10
# 预期：看到 ICMP (ping) 和后续的业务 IP 包

# 5. 全隧道验证（如果 AllowedIPs = 0.0.0.0/0）
curl ifconfig.me
# 预期：显示服务器的公网 IP（说明流量走了 VPN）

# 6. 分流验证（如果 AllowedIPs = 10.0.0.0/24）
curl ifconfig.me
# 预期：显示树莓派自己的公网 IP（普通流量不走 VPN）
ping 10.0.0.1
# 预期：有响应（VPN 网段流量走隧道）
```

### TUN 模式停止

```bash
# 方式1：在运行的终端按 Ctrl+C（优雅关闭，执行 PostDown）

# 方式2：清理残留的 TUN 设备和规则
sudo ./aegis-tunnel tun down
# 删除 tun0 设备、清除路由和 iptables 规则
```

### TUN 配置参数速查

| 配置键 | 位置 | 服务端 | 客户端 | 说明 |
|--------|------|--------|--------|------|
| `Address` | `[Interface]` | `10.0.0.1/24` | `10.0.0.2/24` | TUN 虚拟网卡 CIDR |
| `ListenPort` | `[Interface]` | `9000` | — | 服务端监听端口 |
| `PostUp` | `[Interface]` | 可选 | 可选 | 启动后执行的脚本（`%i` = 网卡名） |
| `PostDown` | `[Interface]` | 可选 | 可选 | 关闭前执行的脚本 |
| `Endpoint` | `[Peer]` | 可选 | **必需** | 服务器真实地址 `host:port` |
| `AllowedIPs` | `[Peer]` | `10.0.0.0/24` | `0.0.0.0/0` | 路由到对端的网段（逗号分隔） |
| `PersistentKeepalive`| `[Peer]` | — | `25` | 保活间隔（秒） |
| `NATInterface` | `[Tunnel]` | `eth0` | — | NAT 出站网卡 |

---

## 4. 传统命令行方式（兼容旧版）

如果不使用四阶段工作流，可以直接用命令行参数启动。适合快速测试和简单场景。

### 代理模式（命令行）

```bash
# 服务端
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server -Q <客户端公钥hex>

# 客户端
./aegis-tunnel -l 9000 -r 服务器IP:9000 -m client -Q <服务端公钥hex>
```

### TUN 模式（命令行）

```bash
# 服务端
sudo ./aegis-tunnel -T 10.0.0.1/24 -W eth0 -m server -Q <客户端公钥hex>

# 客户端（分流：只路由 VPN 网段）
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 10.0.0.0/24 -m client -r 服务器IP:9000 -Q <服务端公钥hex>

# 客户端（全隧道：所有流量走 VPN）
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client -r 服务器IP:9000 -Q <服务端公钥hex>
```

### 命令行参数速查

| 参数 | 说明 | 示例 |
|------|------|------|
| `-l <port>` | 本地监听端口 | `-l 9000` |
| `-r <host:port>` | 远程目标地址 | `-r 1.2.3.4:9000` |
| `-m <mode>` | 运行模式 | `-m server` 或 `-m client` |
| `-T <ip/prefix>` | TUN VPN 模式 + CIDR | `-T 10.0.0.1/24` |
| `-R <network>` | TUN 路由（AllowedIPs） | `-R 10.0.0.0/24` |
| `-W <iface>` | WAN 网卡（NAT 用） | `-W eth0` |
| `-Q <hex\|file>` | 对端公钥 | `-Q a1b2c3...` 或 `-Q peer.pub` |
| `-P <file>` | 私钥文件路径 | `-P /path/to/private.key` |
| `-K <sec>` | Keepalive 间隔 | `-K 30` |
| `-t <sec>` | 握手超时 | `-t 10` |
| `-x <max>` | 最大连接数 | `-x 64` |
| `-v` | 详细日志 | — |
| `-c <file>` | 配置文件路径 | `-c aegis.conf` |

---

## 5. 多客户端管理

TUN 服务端支持多个客户端同时连接（每个客户端需要独立的 TUN IP）。

### 配置方式

```bash
# 添加多个客户端公钥
./aegis-tunnel peer add client-a <公钥A>
./aegis-tunnel peer add client-b <公钥B>
./aegis-tunnel peer add client-c <公钥C>
```

aegis.conf 中会出现多个 `[Peer]` section：
```ini
[Peer]
PublicKey = aaaaaaaa...
Endpoint = client-a

[Peer]
PublicKey = bbbbbbbb...
Endpoint = client-b

[Peer]
PublicKey = cccccccc...
Endpoint = client-c
```

**重要**：每个客户端的 `aegis-client.conf` 中 `Address` 必须不同：
```ini
# client-a 的 aegis-client.conf
Address = 10.0.0.2/24

# client-b 的 aegis-client.conf
Address = 10.0.0.3/24

# client-c 的 aegis-client.conf
Address = 10.0.0.4/24
```

### 查看状态

```bash
./aegis-tunnel peer list
# 输出:
#   Known peers:
#     client-a
#     client-b
#     client-c

./aegis-tunnel status
# 输出完整的密钥和对端状态
```

---

## 6. 抓包验证加密

### 代理模式抓包

```bash
# 终端 1：启动代理服务端
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 -m server

# 终端 2：抓隧道端口的包
sudo tcpdump -i lo -X port 19000

# 终端 3：发送数据
echo "TOP_SECRET_DATA" | nc 127.0.0.1 19001
```

**预期结果**：tcpdump 输出为乱码，搜索不到 `TOP_SECRET_DATA`。

### TUN 模式抓包

```bash
# 在服务器上抓取 TUN 接口的明文包（解密后进入网卡的数据）
sudo tcpdump -i tun0 -n -c 20

# 在服务器上抓取物理网卡上的加密包（隧道流量）
sudo tcpdump -i eth0 -n port 9000 -X -c 5
```

**预期结果**：
- `tun0` 上看到正常的 IP 包（ping、TCP 等）
- `eth0` 端口 9000 上看到加密乱码，无法识别原始 IP 包内容

### 加密帧格式

```
 0      1      2-3         4...(N+3)      (N+4)...(N+19)
+------+------+--------+--------//----+--------//--------+
| type | flags| length |   payload     |    tag (16 B)    |
|  1   |  1   |  2 BE  |  0..65535 B   |                  |
+------+------+--------+--------//----+--------//--------+

0x0000:  0200 0010 a3f2 7c1d e2b5 9f4a ...   ← 帧类型 0x02 (DATA)
0x0010:  c71e d308 6bd4 f9e3 7284 1acf ...   ← 加密负载（AEGIS-128 密文）
0x0020:  5e2b 941f                           ← 认证标签（16 字节）
```

---

## 7. 故障排查

### 通用问题

| 现象 | 原因 | 解决 |
|------|------|------|
| `make` 只生成一个文件 | `.o` 缓存冲突 | `make clean && make` |
| `cannot find -lssl` | 缺少 OpenSSL 开发库 | `sudo apt install libssl-dev` |
| `handshake failed` | 对端公钥不匹配 | 检查双方公钥是否正确，重新 `peer add` |
| `No peer key found` | 未添加对端公钥 | `./aegis-tunnel peer add <name> <hex>` |
| `bind: Address already in use` | 端口被占用 | `ss -tlnp \| grep 9000` 找到并 `kill` |

### TUN 模式问题

| 现象 | 原因 | 解决 |
|------|------|------|
| `TUNSETIFF: Operation not permitted` | 无 root 权限 | `sudo` |
| `/dev/net/tun: No such file` | TUN 模块未加载 | `sudo modprobe tun` |
| 客户端 ping 不通 10.0.0.1 | 路由未生效或 IP 冲突 | 检查 `ip route`，确认双方 Address 在同一子网 |
| 全隧道后无法上网 | fwmark 规则未生效 | 检查 `ip rule list`，确认 SO_MARK 规则存在 |
| NAT 不工作 | iptables 规则未添加 | `sudo iptables -t nat -L POSTROUTING` 检查 |
| 隧道本身连接也走了 TUN（死循环） | fwmark 未设置 | 检查 `ip rule` 和 SO_MARK 配置 |

### 配置文件问题

| 现象 | 原因 | 解决 |
|------|------|------|
| `aegis.conf not found` | 未运行 keygen 或不在当前目录 | `./aegis-tunnel keygen` |
| `Endpoint` 格式错误 | 缺少端口号 | 改为 `host:port` 格式，如 `server.com:9000` |
| `create tun` 生成的 PostUp 被注释 | 安全考量，默认不启用自动防火墙规则 | 手动取消注释或自行配置 iptables |
| `start tun` 选择了错误的配置文件 | 未显式指定 `-c` | `./aegis-tunnel start tun -server -c my-config.conf` |

### 调试技巧

```bash
# 启用详细日志
./aegis-tunnel -v ...

# 或设置环境变量
AEGIS_LOG=debug ./aegis-tunnel start tun -server

# 验证密钥是否正确
./aegis-tunnel status

# 检查 TUN 设备状态
ip addr show tun0
ip link show tun0

# 检查路由
ip route show table main | grep tun0
ip rule list

# 检查防火墙
sudo iptables -t nat -L POSTROUTING -v
sudo iptables -L FORWARD -v

# 手动清理（如果 tun down 失败）
sudo ip link del tun0
sudo ip rule del fwmark 51820 table main
sudo iptables -t nat -F POSTROUTING
sudo iptables -F FORWARD
```
