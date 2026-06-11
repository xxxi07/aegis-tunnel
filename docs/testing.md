# AEGIS-Tunnel 完整测试与使用指南

## 目录

1. [编译与单元测试](#1-编译与单元测试)
2. [实际部署：两台机器建立加密隧道](#2-实际部署两台机器建立加密隧道)
3. [TUN VPN 模式部署](#3-tun-vpn-模式部署)
4. [配置文件方式部署](#4-配置文件方式部署)
5. [多客户端管理](#5-多客户端管理)
6. [抓包验证](#6-抓包验证)
7. [故障排查](#7-故障排查)

---

## 1. 编译与单元测试

```bash
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
make
```

**预期**：6 行 `→ xxx built`

```bash
# 运行全部自动化测试（21 项）
./test-aegis       # 加密算法 12/12
./test-tunnel      # 帧协议 + 握手 7/7
./e2e-test         # 端到端 2/2
./bench-aegis      # 性能基准
```

---

## 2. 实际部署：两台机器建立加密隧道

### 场景

```
树莓派 (客户端)                    服务器 (x86)
10.0.0.2                           192.168.1.100
    │                                  │
    │  想把本地 9000 端口的流量          │
    │  加密后转发到服务器的 8080 端口     │
    │                                  │
    └──────── 加密 TCP ──────────────▶  │
                                       │
                                  解密 → 127.0.0.1:8080
```

### 第一步：服务器上操作

```bash
# 1. 启动一个 Web 服务（模拟你的业务）
python3 -m http.server 8080 &

# 2. 生成密钥
./aegis-tunnel keygen
# 输出：Public key (send to peer):
#        a1b2c3d4e5f6...（复制这行，发给树莓派）
#       Config: aegis.conf

# 3. 添加树莓派的公钥（等树莓派那边生成后发给你）
./aegis-tunnel peer add pi <树莓派的hex公钥>

# 4. 启动服务端
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server
```

### 第二步：树莓派上操作

```bash
# 1. 编译
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel && make

# 2. 生成密钥
./aegis-tunnel keygen
# 输出：Public key (send to peer):
#        f6e5d4c3b2a1...（复制这行，发给服务器）

# 3. 添加服务器的公钥
./aegis-tunnel peer add server <服务器的hex公钥>

# 4. 启动客户端
./aegis-tunnel -l 9000 -r 192.168.1.100:9000 -m client
```

### 第三步：树莓派上测试

```bash
# 现在树莓派的 9000 端口已经加密转发到服务器的 8080
curl http://127.0.0.1:9000/
# 预期：看到 Web 服务的目录列表
```

### 停止

```bash
Ctrl+C   # 现在可以正常响应了
```

---

## 3. TUN VPN 模式部署

### 场景

```
树莓派 (客户端)                    服务器 (x86)
tun0: 10.0.0.2                      tun0: 10.0.0.1
    │                                  │
    │  所有流量走加密隧道               │  NAT 转发到 eth0
    │                                  │
    └──────── 加密 TCP ──────────────▶  │
                                       │
                                  解密 → eth0 → 互联网
```

### 服务器

```bash
# 生成密钥 + 添加客户端公钥（同第 2 节）

# 启动 TUN VPN 服务端
sudo ./aegis-tunnel -T 10.0.0.1/24 -W eth0 -m server
```

**自动执行**：
```
tun_create("tun0")              → 创建虚拟网卡
ip addr add 10.0.0.1/24 dev tun0 → 配 IP
ip link set tun0 up              → 启用
ip route add 10.0.0.0/24 dev tun0→ 路由
echo 1 > /proc/.../ip_forward    → 开启转发
iptables ... MASQUERADE          → NAT
iptables ... FORWARD             → 允许转发
```

### 客户端（树莓派）

```bash
# 只路由服务器所在子网
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 10.0.0.0/24 -m client -r 192.168.1.100:9000

# 或者全隧道模式（所有流量走 VPN）
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client -r 192.168.1.100:9000
```

### 验证

```bash
# 在客户端 ping 服务器 TUN IP
ping 10.0.0.1
# 预期：有响应

# 在服务端查看 TUN 流量
sudo tcpdump -i tun0 -n -c 5
# 预期：看到 ICMP (ping) 包

# 全隧道验证：客户端的外网 IP 变成服务器的
curl ifconfig.me
# 预期：显示服务器的公网 IP
```

### 停止和清理

```bash
sudo ./aegis-tunnel tun down
# 删除 TUN 设备、清除路由、清除 iptables 规则
```

---

## 4. 配置文件方式部署

### 4.1 自动生成配置

```bash
./aegis-tunnel keygen
# → 生成 aegis.conf 到当前目录
# → 生成密钥到 ~/.aegis-tunnel/
```

### 4.2 添加对端（自动更新配置）

```bash
./aegis-tunnel peer add myserver <对端hex公钥>
# → 自动更新 aegis.conf 的 PublicKey 行
```

### 4.3 修改配置（按需）

```bash
# 编辑 aegis.conf
vim aegis.conf
```

```ini
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key   ← 不用改
Port = 9000                                 ← 改端口
Mode = server                               ← server 或 client

[Peer]
PublicKey = ffffffffffffffff...             ← peer add 自动填的

[Tunnel]
NATInterface = eth0                         ← 改成实际网卡名（ip a 查看）
```

### 4.4 启动

```bash
# 自动检测当前目录的 aegis.conf
./aegis-tunnel

# 或显式指定
./aegis-tunnel -c aegis.conf
```

---

## 5. 多客户端管理

```bash
# 服务器添加多个客户端
./aegis-tunnel peer add client-a <公钥A>
./aegis-tunnel peer add client-b <公钥B>
./aegis-tunnel peer add client-c <公钥C>

# 查看所有授权客户端
./aegis-tunnel peer list
# 输出：
#   client-a
#   client-b
#   client-c

# 查看完整状态
./aegis-tunnel status
# 输出：
#   Key storage: /home/user/.aegis-tunnel
#     Private key: .../private.key (exists)
#     Public key:  .../public.key (exists)
#   Known peers:
#     client-a
#     client-b
#     client-c
```

---

## 6. 抓包验证

```bash
# 终端 1：启动隧道服务端
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 -m server

# 终端 2：抓隧道端口的包
sudo tcpdump -i lo -X port 19000

# 终端 3：发送敏感数据
echo "TOP_SECRET_DATA" | nc 127.0.0.1 19001
```

**预期结果**：tcpdump 输出为乱码，搜索不到 `TOP_SECRET_DATA`。

```
0x0000:  0200 0010 a3f2 7c1d e2b5 9f4a ...   ← 帧类型 0x02
0x0010:  c71e d308 6bd4 f9e3 7284 1acf ...   ← 加密负载（乱码）
0x0020:  5e2b 941f                           ← 认证标签
```

---

## 7. 故障排查

| 现象 | 原因 | 解决 |
|------|------|------|
| `Ctrl+C 没反应` | SA_RESTART bug（已修复） | `git pull` 更新到最新 |
| `Peer 'xxx' added` 但启动报 `No peer key` | 多 peer 时需要选一个 | `peer add` 会自动更新 aegis.conf，用 `-c aegis.conf` 启动 |
| `bind: Address already in use` | 端口被 Ctrl+Z 挂起的进程占用 | `ss -tlnp \| grep 9000` 找到并 `kill` |
| `handshake failed` | 对端公钥不匹配 | 检查双方公钥是否正确，重新 `peer add` |
| `TUNSETIFF: Operation not permitted` | 无 root 权限 | `sudo` |
| `/dev/net/tun: No such file` | TUN 模块未加载 | `sudo modprobe tun` |
| `cannot find -lssl` | 缺少 OpenSSL | `sudo apt install libssl-dev` |
| `make` 只生成一个文件 | `.o` 缓存冲突 | `make clean && make` |
