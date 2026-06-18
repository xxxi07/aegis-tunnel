# AEGIS-Tunnel Complete Testing and Usage Guide

## Table of Contents

1. [Build and Unit Tests](#1-build-and-unit-tests)
2. [Proxy Mode: Encrypted TCP Tunnel Between Two Hosts](#2-proxy-mode-encrypted-tcp-tunnel-between-two-hosts)
3. [TUN VPN Mode: Four-Phase Workflow](#3-tun-vpn-mode-four-phase-workflow)
4. [Legacy Command-Line Mode (Backward Compatible)](#4-legacy-command-line-mode-backward-compatible)
5. [Multi-Client Management](#5-multi-client-management)
6. [Packet Capture Verification](#6-packet-capture-verification)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Build and Unit Tests

```bash
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel
make
```

**Expected output**: 6 lines of `→ xxx built`

```bash
# Run all automated tests (23 total)
./test-aegis       # AEGIS-128 encryption algorithm: 13/13
./test-tunnel      # Frame protocol + asymmetric handshake: 8/8
./e2e-test         # End-to-end handshake: 2/2
./bench-aegis      # Performance benchmark (optional)
```

---

## 2. Proxy Mode: Encrypted TCP Tunnel Between Two Hosts

### Scenario

```
Raspberry Pi (client)               Server (x86)
10.0.0.2                              192.168.1.100
    │                                      │
    │  Encrypt TCP traffic from local      │
    │  port 9000, forward to server:8080   │
    │                                      │
    └──────── Encrypted TCP ──────────────▶│
                                           │
                                      Decrypt → 127.0.0.1:8080
```

Proxy mode operates at the TCP layer: the client listens on a local port, encrypts incoming TCP connections and relays them to the server, which decrypts and forwards to the target address.

### Step 1: Server Setup

```bash
# 1. Start a web service (simulating your backend)
python3 -m http.server 8080 &

# 2. Generate keypair
./aegis-tunnel keygen
# Output:
#   Public key (send to peer):
#     a1b2c3d4e5f6...（copy this line, send to Raspberry Pi）
#   Config: aegis.conf

# 3. Add Raspberry Pi's public key (after Pi generates it and sends to you)
./aegis-tunnel peer add pi <pi-64-char-hex-public-key>

# 4. Start proxy server
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server
```

### Step 2: Raspberry Pi (Client) Setup

```bash
# 1. Build
git clone https://github.com/xxxi07/aegis-tunnel.git
cd aegis-tunnel && make

# 2. Generate keypair
./aegis-tunnel keygen
# Output:
#   Public key (send to peer):
#       f6e5d4c3b2a1...（copy this line, send to server）

# 3. Add server's public key
./aegis-tunnel peer add server <server-64-char-hex-public-key>

# 4. Start proxy client
./aegis-tunnel -l 9000 -r 192.168.1.100:9000 -m client
```

### Step 3: Test the Proxy Tunnel

```bash
# On the Raspberry Pi, access local port 9000
# Traffic is automatically encrypted and forwarded to port 8080 on the server
curl http://127.0.0.1:9000/
# Expected: see the directory listing from the server's python http.server
```

### Proxy Mode Configuration Options

| Option | Server | Client | Description |
|--------|--------|--------|-------------|
| `-l <port>` | Listen port | Listen port | Local listen port |
| `-r <host:port>` | Forward target after decrypt | Server address | Remote address |
| `-m <mode>` | `server` | `client` | Run mode |
| `-K <sec>` | Optional | Optional | Keepalive interval (seconds) |
| `-t <sec>` | Optional | Optional | Handshake timeout (seconds, default 5) |
| `-x <max>` | Optional | — | Max concurrent connections (default 32) |

---

## 3. TUN VPN Mode: Four-Phase Workflow

### Scenario

```
Raspberry Pi (client)               Server (x86)
tun0: 10.0.0.2                        tun0: 10.0.0.1
    │                                      │
    │  IP packets over encrypted tunnel    │  NAT forward to eth0 → Internet
    │                                      │
    └──────── Encrypted TCP ──────────────▶│
                                           │
                                      Decrypt → TUN → NAT → eth0
```

TUN mode operates at the IP layer: it creates a virtual network interface, and all IP packets matching the routing rules are sent through the encrypted tunnel to the peer.

### Phase 1: keygen — Generate Keys + Base Config

```bash
# Execute on both server and Raspberry Pi
./aegis-tunnel keygen
```

**Generated artifacts**:
- `~/.aegis-tunnel/private.key` — Private key (binary, permissions 400)
- `~/.aegis-tunnel/public.key` — Public key (hex text, permissions 644)
- `aegis.conf` — Base configuration file (current directory)

**aegis.conf contents**:
```ini
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...    ← This host's public key
Port = 9000
Mode = server

[Tunnel]
Keepalive = 30
NATInterface = eth0
```

**Sample output**:
```
Public key (send to peer):
  cc65dd6af87f0b819f6ac83f1bbc117a33fe217259d23feac2ed40e5326d0707

Config: aegis.conf

Next: get peer's public key, then:
  aegis-tunnel peer add <name> <peer-hex-key>
```

### Phase 2: peer add — Exchange Public Keys

```bash
# On the server: add Raspberry Pi's public key
./aegis-tunnel peer add pi <pi-64-char-hex-public-key>

# On the Raspberry Pi: add server's public key
./aegis-tunnel peer add server <server-64-char-hex-public-key>
```

**aegis.conf after update** (server side example):
```ini
[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...    ← This host's public key

[Tunnel]
Keepalive = 30
NATInterface = eth0

[Peer]
PublicKey = f6e5d4c3b2a1...    ← Raspberry Pi's public key
Endpoint = pi                   ← Peer identifier
```

**Verify**:
```bash
./aegis-tunnel peer list
# Output:
#   Known peers:
#     pi

./aegis-tunnel status
# Output:
#   Key storage: /home/user/.aegis-tunnel
#     Private key: .../private.key (exists)
#     Public key:  .../public.key (exists)
#   Known peers:
#     pi
```

### Phase 3: create tun — Generate TUN Configuration

#### 3a. Server Side

```bash
./aegis-tunnel create tun -server
# Output:
#   TUN server config written to aegis-server.conf
#
#   Review and edit aegis-server.conf if needed, then:
#     sudo ./aegis-tunnel start tun -server
```

**Generated aegis-server.conf**:
```ini
# AEGIS-Tunnel TUN server config (generated from aegis.conf)

[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = cc65dd6af87f...
Mode = server
Address = 10.0.0.1/24           ← TUN virtual interface IP
ListenPort = 9000                ← Listen port (independent of Port)
# PostUp = iptables ...          ← Optional: uncomment to enable automatic NAT rules
# PostDown = iptables ...

[Peer]
PublicKey = f6e5d4c3b2a1...     ← Client public key
AllowedIPs = 10.0.0.0/24        ← Subnets the peer is allowed to access (comma-separated)
# Endpoint = pi

[Tunnel]
Keepalive = 30
NATInterface = eth0              ← Outbound interface for NAT
Timeout = 10
MaxConnections = 64
```

**Edit as needed**:
```bash
vim aegis-server.conf
```
- If the TUN subnet is not `10.0.0.0/24`, modify `Address` and `AllowedIPs`
- Uncomment `PostUp` / `PostDown` to enable automatic NAT configuration
- If the WAN interface is not `eth0`, change `NATInterface`

#### 3b. Client Side

```bash
./aegis-tunnel create tun -client
# Output:
#   TUN client config written to aegis-client.conf
#
#   Review and edit aegis-client.conf if needed, then:
#     sudo ./aegis-tunnel start tun -client
```

**Generated aegis-client.conf**:
```ini
# AEGIS-Tunnel TUN client config (generated from aegis.conf)

[Interface]
PrivateKey = ~/.aegis-tunnel/private.key
PublicKey = f6e5d4c3b2a1...
Mode = client
Address = 10.0.0.2/24           ← Client TUN IP

[Peer]
PublicKey = cc65dd6af87f...     ← Server public key
Endpoint = server:9000           ← Server real address:port
AllowedIPs = 0.0.0.0/0          ← Full tunnel (all traffic via VPN)
PersistentKeepalive = 30

[Tunnel]
Keepalive = 30
NATInterface = eth0
Timeout = 10
MaxConnections = 64
```

**Edit as needed**:
```bash
vim aegis-client.conf
```
- **`Endpoint`**: Change to the server's real IP or hostname + port (e.g., `1.2.3.4:9000`)
- **`AllowedIPs`**:
  - `0.0.0.0/0` → Full tunnel: all traffic goes through the VPN
  - `10.0.0.0/24` → Split tunnel: only VPN subnet traffic goes through the tunnel
  - `10.0.0.0/24,192.168.1.0/24` → Multi-subnet split tunnel

### Phase 4: start tun — Launch the VPN

#### 4a. Start Server

```bash
sudo ./aegis-tunnel start tun -server
```

**Automatic operations performed**:
1. Create TUN virtual interface `tun0`
2. Configure IP address `10.0.0.1/24`
3. Bring interface up
4. Add route `10.0.0.0/24 dev tun0`
5. Enable IP forwarding
6. Add FORWARD firewall rules
7. Execute PostUp script (if configured)
8. Listen for encrypted connections (default port 9000)

**Expected output**:
```
[crypto] x86 AES-NI backend
[tun] created device: tun0 (fd=6)
[tun] tun0: 10.0.0.1/24
[tun] IP forwarding: enabled
[tun] FORWARD rules: tun0 → ACCEPT
[INFO ] [tun-server] tun0 (10.0.0.1/255.255.255.0) :9000 route=10.0.0.0/24 peers=1
```

#### 4b. Start Client

```bash
sudo ./aegis-tunnel start tun -client
```

**Automatic operations performed**:
1. Create TUN virtual interface `tun0`
2. Configure IP address `10.0.0.2/24`
3. Bring interface up
4. Add routes for each AllowedIPs subnet to tun0
5. Set fwmark policy routing
6. Execute PostUp script (if configured)
7. Connect to server and begin encrypted communication

**Expected output**:
```
[crypto] x86 AES-NI backend
[tun] created device: tun0 (fd=6)
[tun] tun0: 10.0.0.2/24
[tun] fwmark 51820: unmarked→table 51820, marked→main
[tun] full tunnel: 0.0.0.0/0 → tun0 (table 51820)
[INFO ] [tun-client] tun0 (10.0.0.2/255.255.255.0) → server.com:9000 route=0.0.0.0/0 (auto-reconnect)
```

### TUN Mode Verification

```bash
# 1. From the client, ping the server's TUN IP
ping 10.0.0.1
# Expected: responses (ICMP packets travel through encrypted tunnel)

# 2. Check TUN interface status
ip addr show tun0
# Expected: shows the configured IP address

# 3. Check routing table
ip route | grep tun0
# Expected: shows route entries via tun0

# 4. On the server, capture TUN traffic
sudo tcpdump -i tun0 -n -c 10
# Expected: see ICMP (ping) and subsequent business IP packets

# 5. Full tunnel verification (if AllowedIPs = 0.0.0.0/0)
curl ifconfig.me
# Expected: shows the server's public IP (traffic goes through VPN)

# 6. Split tunnel verification (if AllowedIPs = 10.0.0.0/24)
curl ifconfig.me
# Expected: shows the client's own public IP (regular traffic bypasses VPN)
ping 10.0.0.1
# Expected: responses (VPN subnet traffic goes through tunnel)
```

### TUN Mode Shutdown

```bash
# Method 1: Press Ctrl+C in the running terminal (graceful shutdown, executes PostDown)

# Method 2: Manually clean up residual TUN device and rules
sudo ./aegis-tunnel tun down
# Removes tun0 device, clears routes and iptables rules
```

### TUN Configuration Quick Reference

| Config Key | Section | Server | Client | Description |
|-----------|---------|--------|--------|-------------|
| `Address` | `[Interface]` | `10.0.0.1/24` | `10.0.0.2/24` | TUN virtual interface CIDR |
| `ListenPort` | `[Interface]` | `9000` | — | Server listen port |
| `PostUp` | `[Interface]` | Optional | Optional | Script to run after start (`%i` = interface name) |
| `PostDown` | `[Interface]` | Optional | Optional | Script to run before stop |
| `Endpoint` | `[Peer]` | Optional | **Required** | Server real address `host:port` |
| `AllowedIPs` | `[Peer]` | `10.0.0.0/24` | `0.0.0.0/0` | Subnets routed to peer (comma-separated) |
| `PersistentKeepalive`| `[Peer]` | — | `25` | Keepalive interval (seconds) |
| `NATInterface` | `[Tunnel]` | `eth0` | — | NAT outbound interface |

---

## 4. Legacy Command-Line Mode (Backward Compatible)

For quick testing and simple scenarios without the four-phase workflow.

### Proxy Mode (CLI)

```bash
# Server
./aegis-tunnel -l 9000 -r 127.0.0.1:8080 -m server -Q <client-hex-public-key>

# Client
./aegis-tunnel -l 9000 -r server-ip:9000 -m client -Q <server-hex-public-key>
```

### TUN Mode (CLI)

```bash
# Server
sudo ./aegis-tunnel -T 10.0.0.1/24 -W eth0 -m server -Q <client-hex-public-key>

# Client (split tunnel: only route VPN subnet)
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 10.0.0.0/24 -m client -r server-ip:9000 -Q <server-hex-public-key>

# Client (full tunnel: all traffic via VPN)
sudo ./aegis-tunnel -T 10.0.0.2/24 -R 0.0.0.0/0 -m client -r server-ip:9000 -Q <server-hex-public-key>
```

### CLI Options Quick Reference

| Option | Description | Example |
|--------|-------------|---------|
| `-l <port>` | Local listen port | `-l 9000` |
| `-r <host:port>` | Remote target address | `-r 1.2.3.4:9000` |
| `-m <mode>` | Run mode | `-m server` or `-m client` |
| `-T <ip/prefix>` | TUN VPN mode + CIDR | `-T 10.0.0.1/24` |
| `-R <network>` | TUN route (AllowedIPs) | `-R 10.0.0.0/24` |
| `-W <iface>` | WAN interface for NAT | `-W eth0` |
| `-Q <hex\|file>` | Peer public key | `-Q a1b2c3...` or `-Q peer.pub` |
| `-P <file>` | Private key file path | `-P /path/to/private.key` |
| `-K <sec>` | Keepalive interval | `-K 30` |
| `-t <sec>` | Handshake timeout | `-t 10` |
| `-x <max>` | Max connections | `-x 64` |
| `-v` | Verbose logging | — |
| `-c <file>` | Config file path | `-c aegis.conf` |

---

## 5. Multi-Client Management

The TUN server supports multiple simultaneous clients (each client needs a unique TUN IP).

### Configuration

```bash
# Add multiple client public keys
./aegis-tunnel peer add client-a <public-key-A>
./aegis-tunnel peer add client-b <public-key-B>
./aegis-tunnel peer add client-c <public-key-C>
```

Multiple `[Peer]` sections appear in aegis.conf:
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

**Important**: Each client's `aegis-client.conf` must have a different `Address`:
```ini
# client-a's aegis-client.conf
Address = 10.0.0.2/24

# client-b's aegis-client.conf
Address = 10.0.0.3/24

# client-c's aegis-client.conf
Address = 10.0.0.4/24
```

### View Status

```bash
./aegis-tunnel peer list
# Output:
#   Known peers:
#     client-a
#     client-b
#     client-c

./aegis-tunnel status
# Output: full key and peer status
```

---

## 6. Packet Capture Verification

### Proxy Mode Capture

```bash
# Terminal 1: Start proxy server
./aegis-tunnel -l 19000 -r 127.0.0.1:19999 -m server

# Terminal 2: Capture tunnel port packets
sudo tcpdump -i lo -X port 19000

# Terminal 3: Send data
echo "TOP_SECRET_DATA" | nc 127.0.0.1 19001
```

**Expected result**: tcpdump shows garbled output; search for `TOP_SECRET_DATA` yields nothing.

### TUN Mode Capture

```bash
# On the server, capture plaintext packets on the TUN interface (decrypted data entering the interface)
sudo tcpdump -i tun0 -n -c 20

# On the server, capture encrypted packets on the physical NIC (tunnel traffic)
sudo tcpdump -i eth0 -n port 9000 -X -c 5
```

**Expected results**:
- `tun0`: normal IP packets visible (ping, TCP, etc.)
- `eth0` port 9000: encrypted ciphertext; raw IP packet content is unrecognizable

### Encrypted Frame Format

```
 0      1      2-3         4...(N+3)      (N+4)...(N+19)
+------+------+--------+--------//----+--------//--------+
| type | flags| length |   payload     |    tag (16 B)    |
|  1   |  1   |  2 BE  |  0..65535 B   |                  |
+------+------+--------+--------//----+--------//--------+

0x0000:  0200 0010 a3f2 7c1d e2b5 9f4a ...   ← Frame type 0x02 (DATA)
0x0010:  c71e d308 6bd4 f9e3 7284 1acf ...   ← Encrypted payload (AEGIS-128 ciphertext)
0x0020:  5e2b 941f                           ← Authentication tag (16 bytes)
```

---

## 7. Troubleshooting

### General Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `make` produces only one file | `.o` cache conflict | `make clean && make` |
| `cannot find -lssl` | OpenSSL dev library missing | `sudo apt install libssl-dev` |
| `handshake failed` | Peer public key mismatch | Verify both sides' public keys, re-run `peer add` |
| `No peer key found` | Peer public key not added | `./aegis-tunnel peer add <name> <hex>` |
| `bind: Address already in use` | Port occupied | `ss -tlnp \| grep 9000` to find and `kill` |

### TUN Mode Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `TUNSETIFF: Operation not permitted` | Not running as root | Use `sudo` |
| `/dev/net/tun: No such file` | TUN module not loaded | `sudo modprobe tun` |
| Client cannot ping 10.0.0.1 | Route not effective or IP conflict | Check `ip route`, verify both Address values are in the same subnet |
| Full tunnel breaks internet access | fwmark rule not effective | Check `ip rule list`, verify SO_MARK rule exists |
| NAT not working | iptables rules not added | `sudo iptables -t nat -L POSTROUTING` to check |
| Tunnel connection itself routed through TUN (loop) | fwmark not set | Check `ip rule` and SO_MARK configuration |

### Config File Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `aegis.conf not found` | keygen not run or not in current directory | `./aegis-tunnel keygen` |
| `Endpoint` format error | Missing port number | Use `host:port` format, e.g., `server.com:9000` |
| `create tun` generates commented PostUp | Security consideration; auto-firewall rules disabled by default | Uncomment manually or configure iptables yourself |
| `start tun` selects wrong config file | No explicit `-c` flag | `./aegis-tunnel start tun -server -c my-config.conf` |

### Debugging Tips

```bash
# Enable verbose logging
./aegis-tunnel -v ...

# Or set environment variable
AEGIS_LOG=debug ./aegis-tunnel start tun -server

# Verify keys are correct
./aegis-tunnel status

# Check TUN device status
ip addr show tun0
ip link show tun0

# Check routes
ip route show table main | grep tun0
ip rule list

# Check firewall
sudo iptables -t nat -L POSTROUTING -v
sudo iptables -L FORWARD -v

# Manual cleanup (if tun down fails)
sudo ip link del tun0
sudo ip rule del fwmark 51820 table main
sudo iptables -t nat -F POSTROUTING
sudo iptables -F FORWARD
```
