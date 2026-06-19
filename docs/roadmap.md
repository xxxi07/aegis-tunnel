# AEGIS-Tunnel 生产就绪改进路线图

## 阶段一：协议安全加固 ✅ 已完成

### 1.1 per-IP 握手速率限制（抗 DoS） ✅

限制每个源 IP 在 60 秒窗口内最多发起 5 次握手，在进入昂贵的 ECDH 计算之前拒绝连接。

```
实现: src/mode_common.c → handshake_rate_check()
集成: mode_psk_server / mode_tun_server / mode_socks5_server
限制: 每 IP 5 次/60s，超过 32 个 IP 时环形缓冲区淘汰
```

### 1.2 定期会话密钥轮换 ✅

每 120 秒自动轮换会话密钥（WireGuard 风格）。复用了已有的 ECDH re-key 机制，此前被禁用。

```
实现: tunnel_init 默认设置 rekey_sec = 120
此前: 所有 mode 文件将 rekey_sec 覆盖为 0（禁用）
机制: ECDH 密钥交换 → 新会话密钥 → nonce 归零
```

### 1.3 握手重放防护强化 ✅

基于 (时间戳, 临时公钥前缀) 组合的滑动窗口重放检测。防止已捕获的握手 init 消息在 ±60 秒窗口内被精确重放。

```
实现: src/protocol/handshake.c → is_replay()
键: (int64_t 时间戳, uint64_t 临时公钥前缀), 128 个槽位
同时刻不同临时公钥的握手互不干扰（不同连接的独立握手）
```

---

## 阶段二：运维能力补全

### 2.1 守护进程模式 + pidfile

**状态**: 计划中
**工作量**: 2 天

```
$ aegis-tunnel start tun -server --daemon --pidfile /run/aegis.pid
$ aegis-tunnel stop --pidfile /run/aegis.pid
$ aegis-tunnel reload  # SIGHUP → 重载 aegis.conf，热加载 peer 列表
```

- `fork()` + `setsid()` 实现守护进程化
- 启动时写 pidfile，检查已有实例防止重复启动
- `SIGHUP`: 重新加载配置，不中断现有连接
- `SIGTERM`: 优雅关闭 + 执行 PostDown 脚本

### 2.2 日志系统升级

**状态**: 计划中
**工作量**: 1 天

- 日志级别: ERROR / WARN / INFO / DEBUG
- 输出目标: stderr | syslog | 文件（命令行可选）
- 文件按大小轮转（默认 10 MB）或按天轮转
- 影响: `src/util/log.c`（约 100 行扩展）

### 2.3 配置文件校验

**状态**: 计划中
**工作量**: 1 天

- `keygen` 后校验必填项（PrivateKey、至少一个 [Peer]）
- `peer add` 时验证 hex 公钥格式和长度
- `start tun` 前预检查（Address 格式、Endpoint 格式）
- 影响: `src/config_mgmt.c` → 新增 `validate_config()` 函数

---

## 阶段三：TCP-over-TCP 优化

### 3.1 TCP 连接池（多路径传输） ✅

**状态**: 已完成
**实现**: `src/mode_tun.c` → `tun_client_multipath()`

```
用法:  -M <1-8>  (默认 1 = 单路径)
实现:  N 条并行 TCP 连接 → N 个子进程 → socketpair → 父进程哈希路由
服务端: 同 peer IP 自动轮询分发回程流量
```

- 每条连接独立握手 + nonce 空间
- 多项式哈希保持流亲和性（同流同路径）
- 某连接重传时其他连接不受影响

### 3.2 UDP 传输模式 ✅

**状态**: 已完成
**实现**: `src/mode_tun_udp.c` (~320 行)

```
用法:  -U  (与 TUN 模式配合)
实现:  每个 IP 包 → 一个 UDP 数据报 → 一个 AEGIS 帧
握手:  复用现有 3-DH 协议（connected UDP socket）
```

- 无应用层重传（内层 TCP 自行负责）
- 保活帧维持 NAT 映射
- 彻底消除 TCP-over-TCP 拥塞嵌套

---

## 阶段四：跨平台支持

### 4.1 macOS / BSD 移植

**状态**: 计划中
**工作量**: 3 天

- macOS: `/dev/tun`（与 Linux `/dev/net/tun` 不同的 ioctl 命令）
- BSD: 与 macOS 类似
- 路由: `route(8)` 替代 `ip(8)`
- 防火墙: `pfctl` 替代 `iptables`
- 封装为 `src/tunnel/tun_darwin.c`（约 200 行）

### 4.2 嵌入式轻量模式

**状态**: 计划中
**工作量**: 2 天

```
$ make MONOCYPHER=1
```

- 用 Monocypher（~1500 行 C，X25519 + SHA-512）替代 OpenSSL
- 条件编译: `#ifdef USE_MONOCYPHER`
- 目标: 静态链接后 < 500 KB
- 适用于: OpenWrt / Yocto / Buildroot

---

## 阶段五：测试与验证

### 5.1 形式化协议验证

**状态**: 计划中
**工作量**: 1 周

- 用 ProVerif/Tamarin 将 AEGIS-128 建模为黑盒 AEAD
- 建模 3-DH 握手流程
- 验证: 密钥保密性、双向认证、前向安全性、重放抵抗
- 产出: `docs/formal-verification.md` + `.pv` 模型文件

### 5.2 压力测试套件

**状态**: 计划中
**工作量**: 2 天

```
tests/stress_test.c:
  - 并发: 100 个客户端 × 1 个服务端
  - 吞吐: 1 Gbps 持续 1 小时
  - 长时: 7 天不间断 tunnel_run()
  - 混沌: 网络断开重连、半开连接、恶意帧注入
```

### 5.3 模糊测试

**状态**: 计划中
**工作量**: 2 天

```
$ make fuzz   # 使用 -fsanitize=fuzzer 编译

目标:
  - frame_reader_try_next(): TCP 流帧解析器
  - frame_parse(): 帧解密 + 认证
  - socks5_accept(): SOCKS5 协议握手
  - iniconf_load(): INI 配置文件解析器
```

### 5.4 单元测试补全（iniconfig + keyfile）

**状态**: 计划中
**工作量**: 1 天

- `tests/test_iniconfig.c`: 节解析、重复键、边界条件
- `tests/test_keyfile.c`: hex 解析、二进制格式、权限检查
- CI 集成: `make test` 中包含

---

## 远期计划：Cookie 抗 DoS 机制

**状态**: 延后（速率限制对大多数部署已足够）

### 设计

当服务端 CPU 压力过大时（ECDH 计算饱和），可以回复明文 COOKIE
帧而非执行昂贵的 ECDH 计算。

```
客户端                                服务端
  │                                      │
  │── HANDSHAKE_INIT ──────────────────▶│  (40 字节，加密)
  │     (eph_pub_c, ts_c)                │
  │                                      │── [如果过载] ──
  │◀── COOKIE_REPLY ───────────────────│  (明文，无 ECDH)
  │     cookie = MAC(sk, eph_c, ip)      │
  │                                      │
  │── HANDSHAKE_INIT + cookie ─────────▶│  (56 字节，加密)
  │     (eph_pub_c, ts_c, cookie)        │
  │                                      │  验证 cookie → ECDH
  │◀── HANDSHAKE_RESP ────────────────│  (正常流程)
```

```
新帧类型: FRAME_COOKIE_REQUEST (0x07), FRAME_COOKIE_REPLY (0x08)
Cookie 公式: SHA256(server_sk || eph_pub_c[0:16] || peer_ip || timestamp)[0:16]
Cookie 有效期: 120 秒
带 Cookie 的 payload 格式: [eph_pub(32)][ts(8)][cookie(16)] = 56 字节
```

### 触发逻辑

```
if (active_handshakes_in_progress > CPU_CORES * 2) {
    send_cookie_reply();   // 延迟 ECDH
} else {
    do_ecdH_handshake();   // 正常流程
}
```

---

## 优先级总览

| 阶段 | 项目 | 优先级 | 工作量 | 状态 |
|------|------|--------|--------|------|
| 1.1 | per-IP 速率限制 | 🔴 关键 | 2h | ✅ 已完成 |
| 1.2 | 定期 re-key (120s) | 🔴 关键 | 1h | ✅ 已完成 |
| 1.3 | 握手重放防护 | 🔴 关键 | 1h | ✅ 已完成 |
| 3.1 | TCP 多路径 | 🟡 高 | 3d | ✅ 已完成 |
| 3.2 | UDP 传输 | 🟡 中 | 1d | ✅ 已完成 |
| 2.3 | 配置校验 | 🟡 高 | 1d | 📋 计划中 |
| 2.1 | 守护进程 + pidfile | 🟡 高 | 2d | 📋 计划中 |
| 2.2 | 日志升级 | 🟡 中 | 1d | 📋 计划中 |
| 5.2 | 压力测试 | 🟡 中 | 2d | 📋 计划中 |
| 5.3 | 模糊测试 | 🟡 中 | 2d | 📋 计划中 |
| 5.4 | 单元测试 | 🟡 中 | 1d | 📋 计划中 |
| 4.1 | macOS 移植 | 🟢 低 | 3d | 📋 计划中 |
| 4.2 | 嵌入式模式 | 🟢 低 | 2d | 📋 计划中 |
| 5.1 | 形式化验证 | 🟢 低 | 1w | 📋 计划中 |
| — | Cookie 抗 DoS | 🟢 延期 | 3d | 📝 已记录 |
