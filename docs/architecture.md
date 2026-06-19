# AEGIS-Tunnel 架构与调用关系图

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           aegis-tunnel CLI                              │
│  keygen | peer add/delete/list | create tun | start tun | socks5 | ... │
└────────────────────────────┬────────────────────────────────────────────┘
                             │ main() 参数解析 + 模式分发
         ┌───────────────────┼───────────────────────┐
         ▼                   ▼                       ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   TUN VPN 模式   │ │   代理模式       │ │  SOCKS5 模式     │
│  mode_tun.c      │ │  mode_psk.c     │ │  mode_socks5.c   │
│  mode_tun_udp.c  │ │                 │ │                  │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                    │
         └───────────────────┼────────────────────┘
                             │
         ┌───────────────────┼───────────────────────┐
         │                   ▼                       │
         │  ┌─────────────────────────────────┐      │
         │  │         隧道引擎 (tunnel.c)       │      │
         │  │  poll() 事件循环 + 帧加解密       │      │
         │  └────────────┬────────────────────┘      │
         │               │                           │
         ▼               ▼                           ▼
┌─────────────────────────────────────────────────────────┐
│                    协议层 (protocol/)                    │
│  handshake.c  — X25519 3-DH 握手 + re-key              │
│  ecdh.c       — X25519 密钥交换 (OpenSSL EVP)           │
│  frame_reader.c — TCP 流帧解析器                       │
│  keyfile.c    — 密钥文件 I/O                           │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│                    加密层 (crypto/)                      │
│  aegis.c      — AEGIS-128 纯 C 实现 + 后端选择          │
│  x86/aegis128-x86.c — AES-NI 加速 (~9500 MB/s)          │
│  neon/aegis128-armcrypto.c — ARM Crypto 加速             │
│  neon/aegis128-plain.c — ARM NEON 加速                   │
└────────────┬────────────────────────────────────────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
┌─────────┐    ┌────────────┐
│ OpenSSL │    │ Linux 内核  │
│ X25519  │    │ TUN / TCP   │
│ SHA256  │    │ UDP / poll  │
└─────────┘    └────────────┘
```

## 2. 外部依赖

```
aegis-tunnel
├── libssl.so       (X25519 ECDH: EVP_PKEY X25519 API)
├── libcrypto.so    (SHA256: EVP_Digest* API)
├── libpthread.so   (线程池，默认使用 fork 故实际未链接)
└── Linux 内核 syscall
    ├── socket() / connect() / accept() / listen()
    ├── send() / recv() / sendto() / recvfrom()
    ├── poll() / read() / write()
    ├── open("/dev/net/tun") + ioctl(TUNSETIFF)
    ├── setsockopt(SO_MARK) — fwmark 策略路由
    ├── fork() + execvp() — 执行 ip/iptables 命令
    └── open("/dev/urandom") — 随机数
```

## 3. 模块详解

### 3.1 入口层 (main.c + config_mgmt.c)

```
main()
├── cmd_keygen()          config_mgmt.c
│   ├── get_real_home()
│   ├── keyfile_generate() → ecdh.c → OpenSSL
│   └── detect_default_iface()
├── cmd_peer_add()        config_mgmt.c
│   ├── get_real_home()
│   └── 读写 ~/.aegis-tunnel/peers/<name>.pub
├── cmd_peer_delete()     config_mgmt.c
│   └── 删除 .pub 文件 + 清理 aegis.conf [Peer]
├── cmd_peer_list()       config_mgmt.c
├── cmd_status()          config_mgmt.c
├── cmd_create_tun()      config_mgmt.c
│   ├── iniconf_load() → iniconfig.c
│   └── 生成 aegis-server/client.conf
├── cmd_tun_down()        config_mgmt.c
│   └── run_cmdv_quiet() → fork+exec(ip/iptables)
└── 模式分发 ────────────┐
                         ▼
    ┌────────────────────────────────────┐
    │ mode selection (aegis_crypto_init) │
    └────────────┬───────────────────────┘
                 │
    ┌────────────┼────────────────────────┐
    ▼            ▼                        ▼
 TUN TCP      TUN UDP                  代理/SOCKS5
 mode_tun    mode_tun_udp
```

### 3.2 TUN TCP 服务端 (mode_tun_server)

```
mode_tun_server()
│
├── tun_create()              打开 /dev/net/tun, ioctl(TUNSETIFF)
├── tun_set_ip()              fork+exec("ip addr add")
├── tun_up()                  fork+exec("ip link set up")
├── tun_setup_routing()       tunt_setup_routing()
│   ├── tun_enable_forwarding()   写 /proc/sys/net/ipv4/ip_forward
│   ├── tun_add_routes_multi()    fork+exec("ip route add")
│   ├── tun_set_nat_multi()       fork+exec("iptables -t nat -A")
│   └── tun_allow_forward()       fork+exec("iptables -A FORWARD")
├── listen_on_port()          socket() + bind() + listen()
│
└── 父进程 poll() 循环 ──────────────────────┐
    │                                         │
    ├── [新连接] accept() ──────────────────┐ │
    │   ├── handshake_rate_check()  抗DoS   │ │
    │   ├── try_handshake_server()          │ │
    │   │   └── handshake_server()          │ │
    │   │       ├── recv_all() ← HANDSHAKE  │ │
    │   │       ├── ecdh_derive() × 3      │ │
    │   │       ├── check_ts() + is_replay()│ │
    │   │       ├── ecdh_keygen()           │ │
    │   │       └── send_all() → HANDSHAKE  │ │
    │   ├── handshake_key_confirm_server()  │ │
    │   ├── socketpair() 创建父子通道       │ │
    │   └── fork() ──────────────────────┐ │ │
    │       │                             │ │ │
    │       ▼ 子进程                      │ │ │
    │   tunnel_init()                     │ │ │
    │   tunnel_run()                      │ │ │
    │   │ poll(tun_child_fd, enc_fd)      │ │ │
    │   │ ├── read(socketpair) → encrypt  │ │ │
    │   │ │   → send(TCP)                 │ │ │
    │   │ └── recv(TCP) → decrypt         │ │ │
    │   │     → write(socketpair)         │ │ │
    │   └─────────────────────────────────┘ │ │
    │                                        │ │
    ├── [TUN→客户端]                        │ │
    │   read(tun_fd) → ip_dst_addr()       │ │
    │   → find_client_by_ip() (轮询)       │ │
    │   → write(socketpair) ──────────────▶│ │
    │                                        │ │
    └── [客户端→TUN]                        │ │
        read(socketpair) ◀───────────────── │ │
        → write(tun_fd)                     │ │
                                            │ │
    ┌───────────────────────────────────────┘ │
    │  keepalive + re-key (120s)              │
    └─────────────────────────────────────────┘
```

### 3.3 TUN TCP 客户端 (mode_tun_client)

```
mode_tun_client()
│
├── tun_create() / tun_set_ip() / tun_up()
├── tun_add_full_tunnel()     全隧道路由
├── tun_set_fwmark_rule()     fwmark 策略路由
│
└── 重连循环
    │
    ├── [单路径 g_tun_multipath=1]
    │   connect_to_host()        getaddrinfo() + socket() + connect()
    │   handshake_client()       X25519 3-DH
    │   handshake_key_confirm_client()
    │   tunnel_init()
    │   tunnel_run()
    │   │ poll(tun_fd, tcp_fd)
    │   │ ├── read(tun_fd) → encrypt → send(tcp_fd)
    │   │ └── recv(tcp_fd) → frame_reader → decrypt → write(tun_fd)
    │   └─────────────────────
    │
    └── [多路径 g_tun_multipath>1]
        tun_client_multipath()
        │
        ├── 连接×N: connect_to_host() × N
        ├── 握手×N: handshake_client() × N
        ├── socketpair() × N + fork() × N
        │
        └── 父进程 poll() ──────────────────┐
            │                                │
            ├── read(tun_fd) → 多项式哈希 → write(sp[hash])
            └── read(sp[i]) ──────────────→ write(tun_fd)
```

### 3.4 TUN UDP 模式 (mode_tun_udp.c)

```
mode_tun_udp_server()                 mode_tun_udp_client()
│                                     │
├── tun_create() / 路由设置            ├── tun_create() / 路由设置
├── socket(SOCK_DGRAM) + bind()       ├── socket(SOCK_DGRAM)
│                                     │   + getaddrinfo() + connect()
└── recvfrom() 等握手                 └── connect() 后:
    │                                     handshake_client()
    ├── 收到 HANDSHAKE_INIT               handshake_key_confirm_client()
    ├── 创建 connected UDP socket         │
    ├── fork()                            └── poll(tun_fd, udp_fd) 循环
    │                                         ├── read(tun_fd)
    │   [子进程]                               │   → frame_build()
    │   handshake_server()                    │   → send(udp_fd)
    │   handshake_key_confirm()               └── recv(udp_fd)
    │   │                                         → frame_parse()
    │   └── poll(tun_fd, udp_fd) 循环              → write(tun_fd)
    │       ├── read(tun_fd) → frame_build() → send(udp_fd)
    │       └── recv(udp_fd) → frame_parse() → write(tun_fd)
    │       keepalive: 每 25s 发送空帧
```

### 3.5 握手协议 (handshake.c)

```
┌─────────── 客户端 ───────────┐     ┌─────────── 服务端 ───────────┐
│                               │     │                               │
│ handshake_client()            │     │ handshake_server()            │
│ ├── ecdh_keygen() → eph_c    │     │ ├── recv_all() ← eph_c, ts_c │
│ ├── asym_init_key()          │     │ ├── ecdh_derive(ee, sk_s, eph_c)
│ │   ├── ecdh_derive(ee,ek,pk)│     │ ├── ecdh_derive(es, sk_s, pk_c)
│ │   └── ecdh_derive(es,sk,pk)│     │ ├── sha256() → init_key      │
│ ├── asym_send() → eph_c,ts_c │     │ ├── check_ts(ts_c, eph_c)    │
│ ├── recv_all() ← eph_s, ts_s │     │ │   ├── ±60s 窗口检查         │
│ │                             │     │ │   └── is_replay() 去重      │
│ ├── ecdh_derive(ee,ek,pk_s) │     │ ├── ecdh_keygen() → eph_s    │
│ ├── ecdh_derive(es,sk,pk_s) │     │ ├── ecdh_derive(ee, sk_s, eph_c)
│ ├── ecdh_derive(se,sk,eph_s)│     │ ├── ecdh_derive(es, sk_s, pk_c)
│ ├── sha256(ee||es||se||"shared") │ ├── ecdh_derive(se, ek_s, pk_c) │
│ │   → shared_secret          │     │ ├── sha256(ee||es||se||"shared")
│ ├── check_ts(ts_s, eph_s)   │     │ │   → shared_secret            │
│ └── asym_sess()→ enc/dec_key│     │ ├── asym_sess()→ enc/dec_key │
│                               │     │ └── asym_send() → eph_s,ts_s │
│ KEY_CONFIRM                  │     │                               │
│ ├── recv_all() ← server kc   │     │ KEY_CONFIRM                   │
│ └── 验证通过                  │     │ └── send_all() → kc frame    │
│                               │     │                               │
│ 非对称密钥交换 (3次 ECDH):     │     │                               │
│ ee = X25519(eph_sk, peer_eph_pk)  │                               │
│ es = X25519(static_sk, peer_eph_pk)                                 │
│ se = X25519(eph_sk, peer_static_pk)                                 │
│ shared = SHA256(ee || es || se || "shared")                        │
│ enc_key = shared[0:16]    dec_key = shared[16:32]                  │
└───────────────────────────────┘     └───────────────────────────────┘
```

### 3.6 帧协议 (tunnel.c + frame_reader.c)

```
┌────────────────── 帧格式（线格式）───────────────────┐
│ type(1) │ flags(1) │ length(2 BE) │ payload(N) │ tag(16) │
└────────────────────────────────────────────────────┘
                     │                │           │
                     │   ←── AD ────→│           │
                     │   ←── AEGIS 认证 ─────────→│

帧类型:
  HANDSHAKE(0x01)    — 握手帧 (60 B 线数据)
  DATA(0x02)         — 加密数据 (4+N+16 B)
  KEEPALIVE(0x03)    — 心跳 (20 B, payload=0)
  CLOSE(0x04)        — 关闭 (20 B, payload=0)
  KEY_CONFIRM(0x05)  — 密钥确认 (20 B, payload=0)
  REKEY(0x06)        — 密钥轮换 (4+32+16 B)

Nonce 构造:
  nonce[16] = little_endian_64(counter) || 0x00 × 8
  每个方向独立计数器，从 1 开始（0 留给握手）

TCP 流帧解析 (frame_reader.c):
  TCP 流到达 → fill_buffer() → 检查是否有完整帧
  → compact() 移动未处理数据 → frame_reader_try_next()
  → frame_parse() 解密 + 认证 → 返回 payload

UDP 帧解析 (mode_tun_udp.c):
  每个 recvfrom() = 一个完整帧 → frame_parse() 直接解密
```

### 3.7 加密后端选择 (aegis.c)

```
aegis_crypto_init()
│
├── if AEGIS_PURE_C=1       → g_encrypt = aegis_pure_encrypt
├── elif __x86_64__         → g_encrypt = aegis128_x86_encrypt
│                              (AES-NI: _mm_aesenc_si128)
├── elif __aarch64__        → aegis128_armcrypto_available()
│   ├── yes                 → g_encrypt = aegis128_armcrypto_encrypt
│   │                         (ARM Crypto: vaeseq_u8 + vaesmcq_u8)
│   └── no                  → g_encrypt = aegis_pure_encrypt
│                              (Pure C: S-Box 查表 + xtime)
│
└── g_encrypt / g_decrypt 函数指针 → aegis_encrypt() / aegis_decrypt()

性能:
  x86 AES-NI:      ~9,500 MB/s  (_mm_aesenc_si128 硬件指令)
  ARM Crypto:      ~1,200 MB/s  (vaeseq_u8 + vaesmcq_u8)
  ARM NEON:        ~3,900 MB/s  (vtbl4q_u8 tbl/tbx 查表)
  Pure C:            ~110 MB/s  (S-Box 数组 + xtime GF乘法)
```

### 3.8 Re-Key 会话密钥轮换

```
tunnel_run() 主循环
│
├── 定时触发 (120s)
│   now - last_rekey >= tun->rekey_sec → goto do_rekey
│
├── Nonce 压力触发
│   enc_nonce >= NONCE_OVERFLOW_LIMIT - 10000 → goto do_rekey
│
└── do_rekey:
    handshake_rekey(fd, session_psk, &keys, &nonce_ctr, init=1)
    │
    ├── ecdh_keygen() → 新临时密钥对
    ├── frame_build(REKEY) + send_all() → 对端
    ├── recv_all() + frame_parse() ← 对端公钥
    ├── ecdh_derive() → 新共享密钥
    ├── SHA256(session_psk || shared || nonce_c || nonce_s)
    │   → 新 enc_key / dec_key
    └── nonce 归零, 密钥原子替换
```

## 4. 数据流全景

```
┌─────── 客户端 ────────────────────────── 服务端 ───────┐
│                                                         │
│ 应用流量 (curl/ping/浏览器)                               │
│     │                                                   │
│     ▼                                                   │
│ ┌──────┐     ┌──────┐          ┌──────┐     ┌──────┐   │
│ │ TUN  │     │SOCKS5│          │SOCKS5│     │ TUN  │   │
│ │ 设备  │     │ 端口  │          │ 端口  │     │ 设备  │   │
│ └──┬───┘     └──┬───┘          └──┬───┘     └──┬───┘   │
│    │            │                 │            │        │
│    │ read IP包  │ socks5_accept() │ connect()   │ read   │
│    ▼            ▼                 ▼            ▼        │
│ ┌──────────────────┐    ┌──────────────────────┐       │
│ │   加密引擎        │    │     加密引擎          │       │
│ │ frame_build()    │    │  frame_parse()       │       │
│ │ aegis_encrypt()  │    │  aegis_decrypt()     │       │
│ │  (AES-NI/ARM/PureC)  │   (AES-NI/ARM/PureC) │       │
│ └────────┬─────────┘    └──────────┬───────────┘       │
│          │                         │                    │
│    send()│ TCP/UDP          recv()│ TCP/UDP            │
│          └─────────┬───────────────┘                    │
│                    │                                    │
│           ┌────────▼────────┐                           │
│           │   物理网络       │                           │
│           │  eth0 / wlan0   │                           │
│           └─────────────────┘                           │
│                                                         │
│  [TCP 模式]   单流 → poll() → 帧协议                     │
│  [多路径模式]  N 流 → 哈希分发 → N× tunnel_run()         │
│  [UDP 模式]    每 IP 包 → 一个数据报                     │
└─────────────────────────────────────────────────────────┘
```

## 5. 配置管理流程

```
keygen
  │
  ├── ~/.aegis-tunnel/private.key  (ecdh_keygen → 32B 二进制)
  ├── ~/.aegis-tunnel/public.key   (hex 编码, 65B 文本)
  └── aegis.conf                   (INI 格式, 含 Interface + Tunnel 节)

peer add <name> <hex>
  │
  ├── ~/.aegis-tunnel/peers/<name>.pub  (64B hex 文本)
  └── aegis.conf 追加 [Peer] 节
      PublicKey = <hex>
      Endpoint = <name>

create tun -server|-client
  │
  ├── iniconf_load("aegis.conf")
  ├── 遍历所有 [Peer] 节 (iniconf_get_indexed)
  ├── 填入 Interface / Peer / Tunnel 配置
  └── 写入 aegis-server.conf 或 aegis-client.conf

start tun -server|-client
  │
  ├── iniconf_load(config.conf)
  ├── 解析: Interface.PrivateKey / Address / ListenPort
  │         Peer.PublicKey / Endpoint / AllowedIPs
  │         Tunnel.Keepalive / NATInterface
  ├── 加载私钥: keyfile_load_private()
  ├── 加载对端公钥: parse_hex() → g_asym_peers[]
  ├── 解析 peer TUN IP: sscanf(AllowedIPs) → g_peer_tun_ips[]
  ├── aegis_crypto_init()  选择加密后端
  └── mode_tun_server() / mode_tun_client()
```

## 6. 关键数据结构

```
g_asym_priv[32]            — 本机 X25519 静态私钥
g_asym_peers[MAX_PEERS][32] — 对端公钥数组
g_peer_tun_ips[MAX_PEERS]  — 对端 TUN IP（网络字节序）
g_peer_endpoints[MAX_PEERS][256] — 对端地址

tunnel_t:
  fd[2]         — [PLAINTEXT, ENCRYPTED] 两个 fd
  enc_key[16]   — 发送方向 AES 密钥
  dec_key[16]   — 接收方向 AES 密钥
  enc_nonce     — 发送计数器 (单调递增)
  dec_nonce     — 接收计数器 (单调递增)
  keepalive_sec — 心跳间隔 (0=关闭)
  rekey_sec     — 密钥轮换间隔 (120s)
  session_psk[16] — 自动派生的 re-key 材料

session_keys_t:
  enc_key[16]   — 加密密钥
  dec_key[16]   — 解密密钥

aegis_state_t:
  S[5][16]      — 5 × 128 位状态字
```

## 7. 安全防线层次

```
┌──────────────────────────────────────┐
│ 第 1 层: 速率限制                     │
│ handshake_rate_check()               │
│ 每 IP 5 次/60s, 环形缓冲区            │
├──────────────────────────────────────┤
│ 第 2 层: 握手认证                     │
│ X25519 3-DH + 时间戳窗口 + 重放检测   │
│ try_handshake_server() → check_ts()  │
├──────────────────────────────────────┤
│ 第 3 层: 密钥确认                     │
│ KEY_CONFIRM 空帧 AEGIS 加密验证       │
│ 防止中间人篡改握手                     │
├──────────────────────────────────────┤
│ 第 4 层: 帧认证                       │
│ 每个帧独立 AEGIS-128 认证标签         │
│ 恒定时间标签比较 (防时序侧信道)        │
│ Nonce 单调递增 (防重放)               │
├──────────────────────────────────────┤
│ 第 5 层: 密钥轮换                     │
│ 每 120s ECDH re-key                 │
│ 密钥原子替换 + nonce 归零             │
└──────────────────────────────────────┘
```
