# AEGIS-Tunnel 已知问题与改进建议

## 一、代码结构问题

### 1.1 main.c 过于臃肿（793 行）

当前 `main.c` 混合了 5 种运行模式：PSK 服务端/客户端、非对称服务端/客户端、TOFU、TUN VPN、SOCKS5 代理。所有模式的分支逻辑都在同一个文件中。

**建议**：拆分为 `src/mode_server.c`、`src/mode_client.c`、`src/mode_tun.c`，main.c 只做参数解析和模式分发。

### 1.2 handshake.c 重复的安全清理代码

`handshake.c` 中有 62 处 `secure_memzero` 调用，大量重复的错误路径清理逻辑。例如：

```c
if (xxx != 0) {
    secure_memzero(ik, 16);
    secure_memzero(epriv, 32);
    return -1;
}
```

这个模式在 PSK 握手和非对称握手中重复了 20+ 次。

**建议**：使用 `goto cleanup` 模式统一清理：
```c
if (xxx != 0) goto fail;
// ...
fail:
    secure_memzero(ik, 16);
    secure_memzero(epriv, 32);
    return -1;
```

### 1.3 线程池已编译但未使用

`src/tunnel/threadpool.c` 实现了 pthread 线程池，但 `main.c` 的 server 模式仍然使用 `fork()` 创建子进程。代码被编译到二进制中但从未被调用。

**建议**：要么接入线程池替换 fork()，要么添加编译选项 `WITH_THREADPOOL` 控制是否编译。

---

## 二、命名不一致

| 问题 | 位置 | 建议 |
|------|------|------|
| `set_to()` vs `set_timeout()` vs `set_socket_timeout()` | handshake.c / main.c / main.c | 统一为 `set_socket_timeout()` |
| `H()` vs `sha256_or_die()` | handshake.c | 统一为 `sha256_or_die()` |
| `asym_` vs `asymmetric_` 前缀 | handshake.c / handshake.h | 统一前缀 |
| `tofu_` vs `TOFU_` 常量 | tofu.c / tofu.h | 常量用大写，函数用小写 |
| `TUNNEL_PLAINTEXT_FD` vs `pt_fd` | tunnel.h / tunnel.c | 统一使用枚举常量 |

---

## 三、安全隐患

### 3.1 TOFU 密钥交换用硬编码 nonce=1

`tofu.c:tofu_exchange_keys()` 中 FRAME_TOFU 的 nonce 硬编码为 1。如果帧丢失或重传，nonce 会重复使用。

**建议**：使用 tunnel 的 monotonic nonce 计数器。

### 3.2 TUN 模式用 system() 调用 iptables

`tun.c:tun_set_nat()` 和 `tun_allow_forward()` 通过 `system()` 执行 shell 命令。如果接口名或子网字符串包含 shell 元字符，存在命令注入风险。

**建议**：改用 Netlink (`libnl`) 或直接操作 `/proc/sys/net/`。

### 3.3 PSK 在进程列表中可见

当使用 `-k <hex>` 传递 PSK 时，PSK 出现在 `/proc/<pid>/cmdline` 中，可被同一主机的其他用户读取。

**建议**：始终推荐使用 `-f <file>` 方式。未来版本可考虑通过管道或环境变量传入。

---

## 四、功能未完成

### 4.1 非对称握手不能独立使用

`handshake_asymmetric_server/client()` 要求提供 PSK 用于 re-keying。如果不提供 PSK，会话内重协商会失败。

**建议**：支持纯非对称模式（无 PSK），re-keying 使用新的 ECDH 交换。

### 4.2 SOCKS5 无 IPv6 支持

`socks5.c` 只处理 ATYP=0x01 (IPv4) 和 ATYP=0x03 (DOMAIN)，不支持 ATYP=0x04 (IPv6)。

### 4.3 无日志文件输出

所有日志输出到 stderr，不支持写入文件、日志轮转。

### 4.4 无连接重试

客户端连接失败后直接退出，没有重试机制。

---

## 五、测试覆盖不足

### 5.1 无模糊测试

帧解析器 `frame_reader.c` 是 TCP 流输入的关键路径，没有模糊测试覆盖。恶意构造的数据包可能导致缓冲区溢出。

**建议**：使用 AFL/libFuzzer 对 `frame_reader_try_next()` 进行模糊测试。

### 5.2 无压力测试

没有并发连接、大数据量、长时运行的稳定性测试。

### 5.3 ARM NEON 从未实际测试

`src/crypto/neon/` 下的两个加速路径（Plain NEON 和 ARM Crypto）代码已编写但从未在真实 ARM 硬件上运行验证。

---

## 六、依赖问题

### 6.1 OpenSSL EVP API

项目强依赖 OpenSSL（SHA256、X25519），无法在无 OpenSSL 的嵌入式系统上编译。

**建议**：未来可考虑集成轻量级实现（如 Monocypher、TweetNaCl）。

### 6.2 Linux 专有 API

TUN 模式 (`/dev/net/tun`)、`getauxval`（ARM 检测）、`send(MSG_NOSIGNAL)` 等是 Linux 特有的，无法在 macOS/BSD 上编译。

---

## 七、改进优先级

| 优先级 | 问题 | 影响 |
|--------|------|------|
| 🔴 高 | TOFU nonce 硬编码 | 帧丢失可能导致 nonce 复用 |
| 🔴 高 | TUN system() 命令注入 | 安全风险 |
| 🟡 中 | main.c 臃肿 | 新功能难以添加 |
| 🟡 中 | handshake.c 重复清理代码 | 维护困难 |
| 🟡 中 | 线程池未使用 | 代码膨胀 |
| 🟢 低 | 命名不一致 | 可读性 |
| 🟢 低 | 无日志文件 | 运维不便 |
| 🟢 低 | SOCKS5 无 IPv6 | 功能不完整 |
