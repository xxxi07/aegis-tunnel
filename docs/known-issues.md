# AEGIS-Tunnel 已知问题与改进计划

## 一、代码结构问题

### 1.1 main.c 臃肿 ✅ 已修复

已拆分为 `main.c`（495 行，参数解析 + 模式分发）、`config_mgmt.c`（配置管理子命令）、`mode_common.c`（共享握手逻辑）。

### 1.2 handshake.c 重复清理代码 ✅ 已修复

通过 `goto out` 统一清理路径，secure_memzero 从 62 处减少到 16 处。

### 1.3 mode_psk.c / mode_tun.c 重复的 try_handshake_server ✅ 已修复

提取到 `src/mode_common.c`，三处模式（psk/tun/socks5）共享同一实现。

### 1.4 线程池编译但未使用 ✅ 构建选项已添加

Makefile 中 `-DWITH_THREADPOOL` 编译选项（默认注释），需要时取消注释即可。

---

## 二、命名一致性 ✅ 已修复

| 问题 | 之前 | 之后 |
|------|------|------|
| 超时函数 | `set_to()` / `set_timeout()` / `set_socket_timeout()` | 统一使用 `recv_all()` 的 `poll()` 超时，移除 SO_RCVTIMEO |
| 哈希函数 | `H()` / `sha256_or_die()` | 统一 `sha256_h()` |
| 前缀 | `asym_` / `asymmetric_` | 统一 `asym_`（内部静态函数） |
| 常量 | `tofu_` / `TOFU_` | 常量大写，函数小写 |

---

## 三、安全隐患

### 3.1 TOFU 硬编码 nonce=1 ✅ 已修复

`tofu_exchange_keys()` 现在接受 `uint64_t *nonce_ctr` 参数，每次使用后递增。

### 3.2 iptables system() 调用 ✅ 全部替换

tun.c 和 config_mgmt.c 中所有 `system()` 调用已替换为 `fork() + execvp()`。`tun_exec_script()` 使用 `execl("/bin/sh", ...)` 显式调用（PostUp/PostDown 本身就是 shell 脚本）。

### 3.3 PSK 在进程列表可见

使用 `-k <hex>` 传递密钥时出现在 `/proc/<pid>/cmdline` 中。始终推荐使用密钥文件方式。

### 3.4 SO_RCVTIMEO 跨平台兼容性 ✅ 已修复

`SO_RCVTIMEO` 在某些内核版本上对 fwmark'd socket 返回虚假 EAGAIN。已用 `poll()` 替代。

### 3.5 gethostbyname 已弃用 ✅ 已修复

替换为线程安全的 `getaddrinfo()`，支持正确的错误报告和地址链遍历。

### 3.6 命令注入漏洞 ✅ 已修复

`cmd_tun_down` 中原 `system(cmd)` 拼接用户输入 `name` 已被 `run_cmdv_quiet()` 替代，`name` 作为独立 argv 元素传递。

---

## 四、功能补全

### 4.1 握手速率限制 ✅ 已实现

per-IP 握手频率限制（5次/60s/IP），在 ECDH 计算前拦截 DoS 攻击。

### 4.2 定期密钥轮换 ✅ 已实现

默认 120 秒自动 re-key，复用已有 ECDH 路径。

### 4.3 握手重放防护 ✅ 已实现

(时间戳, 临时公钥前缀) 滑动窗口检测。

### 4.4 SOCKS5 IPv6 支持

`socks5.c` 仅处理 ATYP=0x01 (IPv4) 和 ATYP=0x03 (DOMAIN)，不支持 ATYP=0x04 (IPv6)。

### 4.5 无日志文件输出

所有日志输出到 stderr，不支持文件写入和日志轮转。

### 4.6 客户端连接重试 ✅ 已实现

`mode_psk.c`、`mode_tun.c`、`mode_socks5.c` 客户端模式均已实现指数退避重连。

---

## 五、测试覆盖不足

### 5.1 无模糊测试

帧解析器 `frame_reader.c` 是 TCP 流入口，恶意构造可能导致缓冲区溢出。建议使用 AFL/libFuzzer。

### 5.2 无压力测试

无并发连接、大数据量、长时运行的稳定性测试。

### 5.3 ARM NEON 尚未硬件验证 ✅ 已在树莓派验证

x86_64 ↔ aarch64 跨平台握手已通过测试。

### 5.4 iniconf / keyfile 单元测试

配置解析器和密钥文件 I/O 缺少独立单元测试。

---

## 六、依赖问题

### 6.1 OpenSSL 依赖

项目强依赖 OpenSSL（SHA256、X25519），无法在无 OpenSSL 的嵌入式系统编译。建议集成 Monocypher 作为轻量替代。

### 6.2 Linux 专有 API

TUN 模式（`/dev/net/tun`）、`SO_MARK`（fwmark）、`ip route`/`iptables` 等 Linux 专有，无法在 macOS/BSD 编译。

---

## 七、改进优先级

| 优先级 | 问题 | 影响 |
|--------|------|------|
| 🔴 高 | — 暂无 — | — |
| 🟡 中 | SOCKS5 无 IPv6 | 功能不完整 |
| 🟡 中 | 无日志文件输出 | 运维不便 |
| 🟡 中 | iniconf/keyfile 无测试 | 可能回归 |
| 🟡 中 | 无模糊测试 | 安全边界 |
| 🟡 中 | 无压力测试 | 稳定性未知 |
| 🟢 低 | OpenSSL 依赖 | 嵌入式受限 |
| 🟢 低 | macOS/BSD 兼容 | Linux only |
