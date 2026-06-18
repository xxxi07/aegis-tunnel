# AEGIS-Tunnel 已知问题与改进建议

## 一、代码结构问题

### 1.1 main.c 过于臃肿 ✅ 已修复

已拆分为 `main.c`（519 行，参数解析 + 模式分发）、`config_mgmt.c`（448 行，配置管理子命令）、`mode_common.c`（17 行，共享握手逻辑）。

### 1.2 handshake.c 重复的安全清理代码 ✅ 已修复

已用 `goto out` 统一清理，secure_memzero 调用从 62 处减少到 16 处。

### 1.3 mode_psk.c / mode_tun.c 重复的 try_handshake_server ✅ 已修复

提取到 `src/mode_common.c`，两处共享同一实现。

### 1.4 线程池已编译但未使用 ✅ 已添加编译选项

Makefile 已添加 `-DWITH_THREADPOOL` 编译选项（默认注释），需要时取消注释即可启用。

---

## 二、命名不一致 ✅ 已修复

| 问题 | 之前 | 之后 |
|------|------|------|
| 超时函数 | `set_to()` / `set_timeout()` / `set_socket_timeout()` | 统一 `recv_all()` 使用 `poll()` 超时，移除 SO_RCVTIMEO |
| 哈希函数 | `H()` / `sha256_or_die()` | 统一 `sha256_h()` |
| 前缀 | `asym_` / `asymmetric_` | 统一 `asym_`（内部静态函数） |
| 常量 | `tofu_` / `TOFU_` | 常量大写，函数小写 |

---

## 三、安全隐患

### 3.1 TOFU 密钥交换用硬编码 nonce=1 ✅ 已修复

`tofu_exchange_keys()` 现在接受 `uint64_t *nonce_ctr` 参数，每次使用后递增。

### 3.2 TUN 模式用 system() 调用 iptables 🔶 部分修复

`tun_set_nat()` 和 `tun_allow_forward()` 已改用 `fork() + execvp()`。`tun_exec_script()` 仍使用 `system()`（因为需要执行用户配置的任意脚本命令，包括管道和分号链）。后续可考虑更安全的 shell 参数化方式。

### 3.3 PSK 在进程列表中可见

当使用 `-k <hex>` 传递 PSK 时，PSK 出现在 `/proc/<pid>/cmdline` 中，可被同一主机的其他用户读取。

**建议**：始终推荐使用 `-f <file>` 方式。未来版本可考虑通过管道或环境变量传入。

### 3.4 SO_RCVTIMEO 跨平台兼容性问题 ✅ 已修复

`SO_RCVTIMEO` 在某些 Linux 内核版本上对 fwmark'd socket 返回虚假的 EAGAIN。已用 `poll()` 替代：`recv_all()` 现在只在 `poll()` 确认 POLLIN 后才调用 `recv()`。

---

## 四、功能未完成

### 4.1 非对称握手不能独立使用 ✅ 已修复

现在默认使用 X25519 3-DH 非对称握手。PSK 仅用于 re-keying bootstrap，且 re-key 默认禁用。纯非对称模式已可用。

### 4.2 SOCKS5 无 IPv6 支持

`socks5.c` 只处理 ATYP=0x01 (IPv4) 和 ATYP=0x03 (DOMAIN)，不支持 ATYP=0x04 (IPv6)。

### 4.3 无日志文件输出

所有日志输出到 stderr，不支持写入文件、日志轮转。

### 4.4 客户端连接重试已实现 ✅ 已修复

`mode_psk.c` 和 `mode_tun.c` 的客户端模式均已实现指数退避重连（1s → 2s → 4s → ... → 30s max）。

---

## 五、测试覆盖不足

### 5.1 无模糊测试

帧解析器 `frame_reader.c` 是 TCP 流输入的关键路径，没有模糊测试覆盖。恶意构造的数据包可能导致缓冲区溢出。

**建议**：使用 AFL/libFuzzer 对 `frame_reader_try_next()` 进行模糊测试。

### 5.2 无压力测试

没有并发连接、大数据量、长时运行的稳定性测试。

### 5.3 ARM NEON 从未实际测试 ✅ 已在树莓派上验证

`src/crypto/neon/` 下的两个加速路径已在真实 ARM 硬件上运行验证，x86_64 ↔ aarch64 跨平台握手已通过测试。

### 5.4 iniconf / keyfile 模块无单元测试 🆕

配置解析器 `iniconfig.c` 和密钥文件 `keyfile.c` 缺少独立的单元测试。

---

## 六、依赖问题

### 6.1 OpenSSL EVP API

项目强依赖 OpenSSL（SHA256、X25519），无法在无 OpenSSL 的嵌入式系统上编译。

**建议**：未来可考虑集成轻量级实现（如 Monocypher、TweetNaCl）。

### 6.2 Linux 专有 API

TUN 模式 (`/dev/net/tun`)、`SO_MARK` (fwmark)、`ip route`/`iptables` 命令等是 Linux 特有的，无法在 macOS/BSD 上编译。

---

## 七、Makefile 与 CMakeLists.txt 不一致 🆕

| 差异点 | Makefile | CMakeLists.txt | 状态 |
|--------|----------|----------------|------|
| AES-NI 编译 | 直接编译进主程序 | 作为静态库链接 | ℹ️ |
| ARM NEON (AEGIS_HAVE_NEON) | ✅ 已添加 | ✅ 已有 | ✅ |
| HAVE_EXPLICIT_BZERO | ❌ 缺失 | ✅ 有 | ℹ️ |
| -lpthread | 总是链接 | 仅 test-tunnel 链接 | ℹ️ |
| ARM -march=armv8-a+crypto | 全局 CFLAGS | 仅 crypto 目标 | ℹ️ |

---

## 八、改进优先级

| 优先级 | 问题 | 影响 |
|--------|------|------|
| 🔴 高 | tun_exec_script() 使用 system() | shell 注入风险 |
| 🟡 中 | SOCKS5 无 IPv6 | 功能不完整 |
| 🟡 中 | 无日志文件输出 | 运维不便 |
| 🟡 中 | iniconf/keyfile 无测试 | 可能回归 |
| 🟡 中 | Makefile/CMake 行为不一致 | ARM 编译差异 |
| 🟢 低 | 无模糊测试 | 安全边界 |
| 🟢 低 | 无压力测试 | 稳定性未知 |
| 🟢 低 | OpenSSL 依赖 | 嵌入式部署受限 |
