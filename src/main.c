/*
 * main.c — AEGIS-Tunnel entry point (argument parsing + dispatch)
 *
 * Asymmetric handshake only. Use aegis-tunnel-keygen to create keys.
 * Subcommand implementations → config_mgmt.c
 * Shared mode helpers       → mode_common.c
 */
#include "main.h"
#include "config_mgmt.h"
#include "protocol/keyfile.h"
#include "util/iniconfig.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PSK_BYTES      64
#define MAX_HOST_LEN       256
#define DEFAULT_MAX_CONN   32
#define DEFAULT_HS_TIMEOUT  5

volatile sig_atomic_t g_active_conns = 0;
volatile sig_atomic_t g_running      = 1;
int   g_max_conns = DEFAULT_MAX_CONN;
int   g_asym_mode = 1;
uint8_t g_asym_priv[32];
uint8_t g_asym_peers[MAX_PEERS][32];
char   g_peer_endpoints[MAX_PEERS][256];
uint32_t g_peer_tun_ips[MAX_PEERS];      /* TUN IP for each peer (network byte order) */
int   g_peer_count = 0;

static void sig_handler(int sig)   { (void)sig; g_running = 0; }
static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) g_active_conns--;
}

/* ─── Utility functions ──────────────────────────────────────────── */

int read_psk_file(uint8_t *psk, size_t max_len, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno)); return -1; }
    ssize_t n = read(fd, psk, max_len); close(fd);
    if (n < 0) { fprintf(stderr, "Error: read '%s': %s\n", path, strerror(errno)); return -1; }
    return (int)n;
}
int parse_hex(uint8_t *out, size_t max, const char *hex) {
    size_t hl = strlen(hex); if (hl % 2) return -1;
    size_t bl = hl/2; if (bl > max) return -1;
    for (size_t i = 0; i < bl; i++) {
        char hi = hex[i*2], lo = hex[i*2+1]; int h, l;
        if      (hi>='0'&&hi<='9') h=hi-'0'; else if (hi>='a'&&hi<='f') h=hi-'a'+10;
        else if (hi>='A'&&hi<='F') h=hi-'A'+10; else return -1;
        if      (lo>='0'&&lo<='9') l=lo-'0'; else if (lo>='a'&&lo<='f') l=lo-'a'+10;
        else if (lo>='A'&&lo<='F') l=lo-'A'+10; else return -1;
        out[i] = (uint8_t)((h<<4)|l);
    }
    return (int)bl;
}
int parse_host_port(char *addr, char **host, int *port) {
    char *colon = strrchr(addr, ':'); if (!colon) return -1;
    *colon = '\0'; *host = addr; *port = atoi(colon + 1);
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}
int connect_to_host(const char *host, int port, int fwmark) {
    /* Resolve host using getaddrinfo (thread-safe, modern, IPv4/IPv6 capable) */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;       /* IPv4 only for now */
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(host, port_str, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "Error: cannot resolve '%s': %s\n", host, gai_strerror(gai_err));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        /* Set fwmark BEFORE connect so the TCP SYN bypasses TUN routes */
        if (fwmark > 0)
            setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;  /* success */

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) { perror("connect"); return -1; }
    return fd;
}
int listen_on_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) { perror("socket"); return -1; }
    int opt = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); close(fd); return -1; }
    if (listen(fd, SOMAXCONN) < 0) { perror("listen"); close(fd); return -1; }
    return fd;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -c <config.conf>  (WireGuard-style, one file)\n"
        "       %s -r <host:port> [options]\n"
        "\n"
        "AEGIS-Tunnel -- Lightweight encrypted tunnel using AEGIS-128 AEAD\n"
        "\n"
        "Commands (recommended workflow):\n"
        "  keygen                         Generate keys + aegis.conf\n"
        "  peer add <name> <hex|file>     Add peer's public key\n"
        "  peer delete <name>             Remove peer's public key\n"
        "  peer list                      List known peers\n"
        "  create tun -server|-client      Generate TUN config from aegis.conf\n"
        "  start tun -server|-client       Start TUN VPN from config\n"
        "  socks5 -server|-client           SOCKS5 proxy mode (no root needed)\n"
        "  tun down [name]                Remove TUN device + iptables rules\n"
        "  status                         Show key/peer status\n"
        "\n"
        "TUN workflow:\n"
        "  %s keygen                           # step 1\n"
        "  %s peer add myserver <peer-hex>     # step 2\n"
        "  %s create tun -server               # step 3\n"
        "  sudo %s start tun -server           # step 4\n"
        "\n"
        "Quick start (legacy, no config file):\n"
        "  -l <port>       Local listen port (default 9000)\n"
        "  -r <host:port>  Remote target\n"
        "  -m <mode>       'server' or 'client'\n"
        "  -T <ip/prefix>  TUN VPN: e.g. -T 10.0.0.1/24\n"
        "  -P <file>       Private key path\n"
        "  -Q <hex|file>   Peer public key (64 hex chars or file)\n"
        "  -C <file>       Config file\n"
        "  -t <sec>        Handshake timeout (default: 5)\n"
        "  -x <max>        Max connections (default: 32)\n"
        "  -K <sec>        Keepalive (default: 0)\n"
        "  -W <iface>      WAN interface for NAT (default: eth0)\n"
        "  -v              Verbose logging\n"
        "  -h              Show this help\n"
        "\n",
        prog, prog, prog, prog, prog, prog);
}

/* ══════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv) {
    /* Subcommands: aegis-tunnel keygen | peer add <host> <hex> | peer list */
    int  start_tun_force   = 0;  /* 1=server, 2=client — set by 'start tun' subcommand */
    int  socks5_force      = 0;  /* 1=server, 2=client — set by 'socks5' subcommand */
    if (argc >= 2) {
        if (!strcmp(argv[1], "keygen"))    return cmd_keygen();
        if (!strcmp(argv[1], "status"))    return cmd_status();
        if (!strcmp(argv[1], "tun") && argc >= 3 && !strcmp(argv[2], "down"))
                                           return cmd_tun_down(argc >= 4 ? argv[3] : "tun0");
        if (!strcmp(argv[1], "peer") && argc >= 3) {
            if (!strcmp(argv[2], "list"))  return cmd_peer_list();
            if (!strcmp(argv[2], "add") && argc >= 5) return cmd_peer_add(argv[3], argv[4]);
            if (!strcmp(argv[2], "delete") && argc >= 4) return cmd_peer_delete(argv[3]);
            fprintf(stderr, "Usage: %s peer add <name> <hex-or-file>\n", argv[0]);
            fprintf(stderr, "       %s peer list\n", argv[0]);
            fprintf(stderr, "       %s peer delete <name>\n", argv[0]);
            return 1;
        }
        /* create tun -server | -client */
        if (!strcmp(argv[1], "create") && argc >= 4 && !strcmp(argv[2], "tun")) {
            if (!strcmp(argv[3], "-server")) return cmd_create_tun(1);
            if (!strcmp(argv[3], "-client")) return cmd_create_tun(0);
            fprintf(stderr, "Usage: %s create tun -server | -client\n", argv[0]);
            return 1;
        }
        /* start tun -server | -client */
        if (!strcmp(argv[1], "start") && argc >= 4 && !strcmp(argv[2], "tun")) {
            if (!strcmp(argv[3], "-server"))      start_tun_force = 1;
            else if (!strcmp(argv[3], "-client")) start_tun_force = 2;
            else {
                fprintf(stderr, "Usage: %s start tun -server | -client [-c <config>]\n", argv[0]);
                return 1;
            }
            /* Consume subcommand args so getopt sees only remaining flags (like -c) */
            argv += 3; argc -= 3;
            optind = 0;  /* reset getopt for shifted argv */
        }
        /* socks5 -server | -client */
        if (!strcmp(argv[1], "socks5") && argc >= 3) {
            if (!strcmp(argv[2], "-server"))      socks5_force = 1;
            else if (!strcmp(argv[2], "-client")) socks5_force = 2;
            else {
                fprintf(stderr, "Usage: %s socks5 -server | -client [-l <port>] [-r <host:port>]\n",
                        argv[0]);
                return 1;
            }
            argv += 2; argc -= 2;
            optind = 0;
        }
    }

    int  listen_port = 9000;  /* default port */
    char *remote_str = NULL, *config_file = NULL;
    char *privkey_file = NULL, *peerkey_file = NULL;
    const char *mode = "server";
    int  keepalive = 0, hs_timeout = DEFAULT_HS_TIMEOUT;
    int  tun_mode = 0;
    char tun_name[16] = "tun0", tun_ip[32] = "", tun_netmask[32] = "255.255.255.0";
    char tun_route[64] = ""; char tun_nat_if[16] = "";  /* auto-detect below */
    if (!tun_nat_if[0]) strncpy(tun_nat_if, detect_default_iface(), 15);
    char tun_postup[256] = "", tun_postdown[256] = "";

    int opt;
    while ((opt = getopt(argc, argv, "l:r:P:Q:C:c:m:t:x:K:T:I:N:R:W:vh")) != -1) {
        switch (opt) {
        case 'l': listen_port = atoi(optarg);           break;
        case 'r': remote_str  = optarg;                break;
        case 'P': privkey_file = optarg;               break;
        case 'Q': peerkey_file = optarg;               break;
        case 'C': config_file = optarg;                break;
        case 'c': config_file = optarg;                break;  /* alias */
        case 'm': mode        = optarg;                break;
        case 't': hs_timeout  = atoi(optarg);           break;
        case 'x': g_max_conns = atoi(optarg);           break;
        case 'K': keepalive   = atoi(optarg);           break;
        case 'T': tun_mode = 1;
                  if (strchr(optarg, '/')) {
                      /* CIDR: 10.0.0.1/24 */
                      char *slash = strchr(optarg, '/');
                      *slash = '\0';
                      strncpy(tun_ip, optarg, 31);
                      int prefix = atoi(slash + 1);
                      *slash = '/';
                      /* Convert prefix to netmask */
                      uint32_t nm = (prefix == 0) ? 0 : (~0u << (32 - (unsigned)prefix));
                      snprintf(tun_netmask, 31, "%u.%u.%u.%u",
                               (nm >> 24) & 0xff, (nm >> 16) & 0xff,
                               (nm >> 8) & 0xff, nm & 0xff);
                      /* Auto-derive route from IP + prefix */
                      char *dot = strrchr(tun_ip, '.');
                      if (dot) { *dot = '\0'; snprintf(tun_route, 63, "%s.0/%d", tun_ip, prefix); *dot = '.'; }
                  } else {
                      strncpy(tun_ip, optarg, 31);
                  }
                  break;
        case 'I': strncpy(tun_ip, optarg, 31);           break;
        case 'N': strncpy(tun_netmask, optarg, 31);      break;
        case 'R': strncpy(tun_route, optarg, 63);         break;
        case 'W': strncpy(tun_nat_if, optarg, 15);        break;
        case 'v': log_set_level(LOG_DEBUG);             break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* ── 'start tun' auto-config selection ── */
    if (start_tun_force) {
        tun_mode = 1;
        if (start_tun_force == 1) mode = "server"; else mode = "client";
        if (!config_file) {
            const char *auto_cfg = (start_tun_force == 1) ? "aegis-server.conf" : "aegis-client.conf";
            if (access(auto_cfg, F_OK) == 0)
                config_file = (char *)auto_cfg;
            else {
                fprintf(stderr, "Error: %s not found.\n", auto_cfg);
                fprintf(stderr, "Run: aegis-tunnel create tun -%s\n",
                        start_tun_force == 1 ? "server" : "client");
                return 1;
            }
        }
    }

    /* ── Auto-detect config file if not specified ── */
    if (!config_file && access("aegis.conf", F_OK) == 0)
        config_file = "aegis.conf";

    /* ── Load config file (INI format, WireGuard-style) ── */
    if (config_file) {
        iniconf_t icfg;
        if (iniconf_load(&icfg, config_file) == 0) {
            /* [Interface] */
            if (listen_port == 9000) {
                int lp = iniconf_get_int(&icfg, "Interface", "ListenPort", 0);
                if (lp > 0) listen_port = lp;
                else listen_port = iniconf_get_int(&icfg, "Interface", "Port", listen_port);
            }
            if (!tun_postup[0]) {
                const char *v = iniconf_get(&icfg, "Interface", "PostUp");
                if (v) strncpy(tun_postup, v, 255);
            }
            if (!tun_postdown[0]) {
                const char *v = iniconf_get(&icfg, "Interface", "PostDown");
                if (v) strncpy(tun_postdown, v, 255);
            }
            if (!remote_str) {
                const char *v = iniconf_get(&icfg, "Peer", "Endpoint");
                if (v) {
                    if (strcmp(v, "0.0.0.0:0") == 0)
                        remote_str = NULL;
                    else
                        remote_str = strdup(v);
                }
            }
            if (!strcmp(mode, "server")) {
                const char *v = iniconf_get(&icfg, "Interface", "Mode");
                if (v && (strstr(v, "client") || strstr(v, "Client"))) mode = "client";
            }
            if (!privkey_file) {
                const char *v = iniconf_get(&icfg, "Interface", "PrivateKey");
                if (v) {
                    if (v[0] == '~') {
                        const char *home = get_real_home();
                        size_t explen = strlen(home) + strlen(v) + 1;
                        char *exp = (char*)malloc(explen);
                        if (exp) snprintf(exp, explen, "%s%s", home, v + 1);
                        privkey_file = exp;
                    } else privkey_file = strdup(v);
                }
            }
            /* Load peer keys + endpoints from config (iterate all [Peer] sections) */
            if (!peerkey_file) {
                int pi = 0;
                while (pi < MAX_PEERS) {
                    const char *v = iniconf_get_indexed(&icfg, "Peer", pi, "PublicKey");
                    if (!v) break;
                    if (strlen(v) == 64) {
                        if (parse_hex(g_asym_peers[pi], 32, v) == 32) {
                            const char *ep = iniconf_get_indexed(&icfg, "Peer", pi, "Endpoint");
                            if (ep) {
                                strncpy(g_peer_endpoints[pi], ep, 255);
                                g_peer_endpoints[pi][255] = '\0';
                            } else {
                                g_peer_endpoints[pi][0] = '\0';
                            }
                            /* Extract peer's TUN IP from AllowedIPs (e.g. "10.0.0.2/32" → 10.0.0.2) */
                            {
                                const char *aip = iniconf_get_indexed(&icfg, "Peer", pi, "AllowedIPs");
                                g_peer_tun_ips[pi] = 0;
                                if (aip) {
                                    uint32_t oct[4]; int pf = 0;
                                    if (sscanf(aip, "%u.%u.%u.%u/%d",
                                               &oct[0], &oct[1], &oct[2], &oct[3], &pf) >= 4) {
                                        g_peer_tun_ips[pi] =
                                            (oct[0] << 24) | (oct[1] << 16) |
                                            (oct[2] << 8)  | oct[3];
                                    }
                                }
                            }
                            g_peer_count = pi + 1;
                        }
                    }
                    pi++;
                }
                if (g_peer_count > 0)
                    log_info("main", "%d peer(s) from config", g_peer_count);
            }
            /* Parse AllowedIPs first (takes priority over Address auto-derive) */
            if (!tun_route[0]) {
                const char *v = iniconf_get(&icfg, "Peer", "AllowedIPs");
                if (v) strncpy(tun_route, v, 63);
            }
            if (!tun_ip[0]) {
                const char *v = iniconf_get(&icfg, "Interface", "Address");
                if (v) {
                    tun_mode = 1;
                    char *slash = strchr((char *)v, '/');
                    if (slash) {
                        size_t ip_len = (size_t)(slash - v);
                        if (ip_len < 32) { memcpy(tun_ip, v, ip_len); tun_ip[ip_len] = '\0'; }
                        int px = atoi(slash + 1);
                        uint32_t nm = (px == 0) ? 0 : (~0u << (unsigned)(32 - px));
                        snprintf(tun_netmask, 31, "%u.%u.%u.%u",
                                 (nm>>24)&0xff, (nm>>16)&0xff, (nm>>8)&0xff, nm&0xff);
                        if (!tun_route[0]) {
                            char *dot = strrchr(tun_ip, '.');
                            if (dot) { *dot = '\0'; snprintf(tun_route, 63, "%s.0/%d", tun_ip, px); *dot = '.'; }
                        }
                    }
                }
            }
            if (keepalive == 0)
                keepalive = iniconf_get_int(&icfg, "Peer", "PersistentKeepalive", 0);
            if (hs_timeout == DEFAULT_HS_TIMEOUT)
                hs_timeout = iniconf_get_int(&icfg, "Tunnel", "Timeout", hs_timeout);
            if (keepalive == 0)
                keepalive = iniconf_get_int(&icfg, "Tunnel", "Keepalive", keepalive);
            if (g_max_conns == DEFAULT_MAX_CONN)
                g_max_conns = iniconf_get_int(&icfg, "Tunnel", "MaxConnections", g_max_conns);
            { const char *v = iniconf_get(&icfg, "Tunnel", "NATInterface");
              if (v) strncpy(tun_nat_if, v, 15); }
            iniconf_free(&icfg);
            log_info("main", "loaded config from %s", config_file);
        }
    }

    if (listen_port <= 0) { fprintf(stderr, "Error: invalid port\n"); return 1; }
    if (!remote_str && !tun_mode && strcmp(mode, "server")) {
        fprintf(stderr, "Error: -r <host:port> is required\n"); usage(argv[0]); return 1; }
    if (strcmp(mode,"server") && strcmp(mode,"client")) { fprintf(stderr, "Error: mode must be server or client\n"); return 1; }

    /* Rekey bootstrap */
    uint8_t psk[MAX_PSK_BYTES]; random_bytes(psk, 16);
    size_t psk_len = 16;

    char remote_host[MAX_HOST_LEN]; int remote_port = 0; char *hp = NULL;
    if (remote_str) {
        char *ac = strdup(remote_str);
        if (!ac) { perror("strdup"); return 1; }
        if (parse_host_port(ac, &hp, &remote_port) != 0) {
            fprintf(stderr, "Error: '%s' format: host:port\n", remote_str);
            free(ac); return 1;
        }
        strncpy(remote_host, hp, MAX_HOST_LEN-1); remote_host[MAX_HOST_LEN-1]='\0';
        free(ac);
    } else {
        remote_host[0] = '\0';
    }

    /* Default key paths: ~/.aegis-tunnel/ */
    char key_dir[768], default_priv[768];
    { const char *home = get_real_home();
      snprintf(key_dir, sizeof(key_dir), "%s/.aegis-tunnel", home);
      mkdir(key_dir, 0700); }

    if (!privkey_file) {
        snprintf(default_priv, sizeof(default_priv), "%s/private.key", key_dir);
        if (access(default_priv, F_OK) != 0) {
            char pub_path[768];
            snprintf(pub_path, sizeof(pub_path), "%s/public.key", key_dir);
            log_info("main", "auto-generating keypair in %s", key_dir);
            keyfile_generate(default_priv, pub_path);
        }
        privkey_file = default_priv;
    }
    if (keyfile_load_private(g_asym_priv, privkey_file) != 0) return 1;

    /* Peer key: support hex string OR file path */
    if (peerkey_file) {
        size_t qlen = strlen(peerkey_file);
        if (qlen == 64 && !strchr(peerkey_file, '/') && !strchr(peerkey_file, '.')) {
            if (parse_hex(g_asym_peers[0], 32, peerkey_file) != 32) {
                fprintf(stderr, "Error: -Q hex key must be 64 hex characters\n");
                return 1;
            }
            g_peer_count = 1;
            log_info("main", "peer key from hex string");
        } else {
            if (keyfile_load_public(g_asym_peers[0], peerkey_file) != 0) return 1;
            g_peer_count = 1;
            log_info("main", "peer key from file: %s", peerkey_file);
        }
    } else if (g_peer_count == 0) {
        /* No peer from config or -Q → auto-detect from ~/.aegis-tunnel/peers/ */
        char peer_dir[768];
        snprintf(peer_dir, sizeof(peer_dir), "%s/peers", key_dir);
        mkdir(peer_dir, 0700);

        int peer_count = 0;
        char found_peer[768] = "";
        {
            DIR *d = opendir(peer_dir);
            if (d) {
                struct dirent *e;
                while ((e = readdir(d))) {
                    size_t nl = strlen(e->d_name);
                    if (nl > 4 && !strcmp(e->d_name + nl - 4, ".pub")) {
                        peer_count++;
                        snprintf(found_peer, sizeof(found_peer), "%s/%s", peer_dir, e->d_name);
                    }
                }
                closedir(d);
            }
        }

        if (peer_count >= 1) {
            if (keyfile_load_public(g_asym_peers[0], found_peer) != 0) return 1;
            if (peer_count > 1)
                log_info("main", "%d peers found, using first: %s", peer_count, found_peer);
            else
                log_info("main", "using peer key: %s", found_peer);
        } else {
            fprintf(stderr, "\n═══ No peer key found ═══\n");
            fprintf(stderr, "Your public key (send to peer):\n  ");
            {
                char pub_path[768];
                snprintf(pub_path, sizeof(pub_path), "%s/public.key", key_dir);
                uint8_t our_pub[32];
                if (keyfile_load_public(our_pub, pub_path) == 0) {
                    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", our_pub[i]);
                }
            }
            fprintf(stderr, "\n\nAdd peer's key, then run again:\n");
            fprintf(stderr, "  aegis-tunnel peer add <name> <peer-hex-key>\n");
            fprintf(stderr, "  %s -l %d -r %s\n", argv[0], listen_port, remote_str);
            return 1;
        }
    }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = sigchld_handler; sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Select the fastest crypto backend for this platform */
    aegis_crypto_init();

    int ret;

    /* ── SOCKS5 proxy mode ── */
    if (socks5_force) {
        if (socks5_force == 1)
            ret = mode_socks5_server(listen_port, psk, psk_len, hs_timeout, keepalive);
        else
            ret = mode_socks5_client(remote_str ? remote_str : "127.0.0.1",
                                     remote_port ? remote_port : 9000,
                                     listen_port, psk, psk_len, hs_timeout, keepalive);
        return ret;
    }

    if (tun_mode) {
        if (!strcmp(mode, "server"))
            ret = mode_tun_server(listen_port, tun_name, tun_ip, tun_netmask,
                                  tun_route[0]?tun_route:NULL, tun_nat_if,
                                  tun_postup[0]?tun_postup:NULL,
                                  tun_postdown[0]?tun_postdown:NULL,
                                  psk, psk_len, hs_timeout, keepalive);
        else
            ret = mode_tun_client(listen_port, remote_host, remote_port,
                                  tun_name, tun_ip, tun_netmask,
                                  tun_route[0]?tun_route:NULL,
                                  tun_postup[0]?tun_postup:NULL,
                                  tun_postdown[0]?tun_postdown:NULL,
                                  psk, psk_len, hs_timeout, keepalive);
    } else if (!strcmp(mode, "server")) {
        ret = mode_psk_server(listen_port, remote_host, remote_port,
                              psk, psk_len, hs_timeout, keepalive);
    } else {
        ret = mode_psk_client(listen_port, remote_host, remote_port,
                              psk, psk_len, hs_timeout, keepalive);
    }
    return ret;
}
