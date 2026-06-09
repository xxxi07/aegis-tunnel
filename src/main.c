/*
 * main.c — AEGIS-Tunnel entry point
 *
 * A lightweight encrypted tunnel using AEGIS-128 authenticated
 * encryption with ARM NEON acceleration.
 *
 * Usage:
 *   aegis-tunnel -l <port> -r <host:port> -k <hex> | -f <file>
 *                [-m server|client] [-t <sec>] [-c <max>] [-K <sec>]
 *
 * Options:
 *   -l <port>      Local listen port (required)
 *   -r <host:port> Remote target address (required)
 *   -k <hex>       PSK as hex string (min 32 hex chars = 16 bytes)
 *   -f <file>      PSK from file (recommended over -k for security)
 *   -m <mode>      'server' (default) or 'client'
 *   -t <sec>       Handshake timeout in seconds (default: 5)
 *   -c <max>       Max concurrent connections (default: 32 server, 16 client)
 *   -K <sec>       Keepalive interval in seconds (default: 0 = disabled)
 *   -h             Show help
 */

#include "protocol/handshake.h"
#include "protocol/keyfile.h"
#include "tunnel/threadpool.h"
#include "tunnel/tun.h"
#include "tunnel/tunnel.h"
#include "util/config.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ─── Configuration ────────────────────────────────────────────── */

#define MAX_PSK_BYTES     64
#define MAX_HOST_LEN      256
#define DEFAULT_MAX_CONN  32
#define DEFAULT_HS_TIMEOUT 5

/*
 * Connection limiter: atomic counter shared between parent (SIGCHLD)
 * and the accept loop.  sig_atomic_t ensures signal-safe reads.
 */
static volatile sig_atomic_t g_active_conns = 0;
static volatile sig_atomic_t g_running = 1;
static int g_max_conns = DEFAULT_MAX_CONN;
static int g_asym_mode = 0;
static uint8_t g_asym_priv[32];
static uint8_t g_asym_peer[32];

/* ─── Signal handlers ──────────────────────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void sigchld_handler(int sig)
{
    (void)sig;
    /* Reap all zombie children without blocking */
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        g_active_conns--;
    }
}

/* ─── Read PSK from file ───────────────────────────────────────── */

static int read_psk_file(uint8_t *psk, size_t max_len, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open PSK file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    ssize_t n = read(fd, psk, max_len);
    close(fd);

    if (n < 0) {
        fprintf(stderr, "Error: cannot read PSK file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    if (n < HANDSHAKE_PSK_MIN_LEN) {
        fprintf(stderr, "Error: PSK file must contain at least %d bytes (got %zd)\n",
                HANDSHAKE_PSK_MIN_LEN, n);
        return -1;
    }

    return (int)n;
}

/* ─── Parse hex string into bytes ──────────────────────────────── */

static int parse_hex(uint8_t *out, size_t out_max, const char *hex)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;

    size_t byte_len = hex_len / 2;
    if (byte_len > out_max) return -1;

    for (size_t i = 0; i < byte_len; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        int h, l;

        if      (hi >= '0' && hi <= '9') h = hi - '0';
        else if (hi >= 'a' && hi <= 'f') h = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') h = hi - 'A' + 10;
        else return -1;

        if      (lo >= '0' && lo <= '9') l = lo - '0';
        else if (lo >= 'a' && lo <= 'f') l = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') l = lo - 'A' + 10;
        else return -1;

        out[i] = (uint8_t)((h << 4) | l);
    }
    return (int)byte_len;
}

/* ─── Parse host:port string ───────────────────────────────────── */

static int parse_host_port(char *addr_str, char **host, int *port)
{
    char *colon = strrchr(addr_str, ':');
    if (!colon) return -1;
    *colon = '\0';
    *host = addr_str;
    *port = atoi(colon + 1);
    if (*port <= 0 || *port > 65535) return -1;
    return 0;
}

/* ─── Connect to remote host:port ──────────────────────────────── */

static int connect_to_host(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Error: cannot resolve host '%s'\n", host);
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    addr.sin_port = htons((uint16_t)port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

/* ─── Listen on local port ─────────────────────────────────────── */

static int listen_on_port(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

/* ─── Set socket timeout ───────────────────────────────────────── */

static void set_socket_timeout(int fd, int seconds)
{
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ─── Usage ────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -l <port> -r <host:port> (-k <hex> | -f <file>) [options]\n"
        "       %s -C <config.conf>  (read all settings from file)\n"
        "\n"
        "AEGIS-Tunnel -- Lightweight encrypted tunnel using AEGIS-128 AEAD\n"
        "\n"
        "Required:\n"
        "  -l <port>       Local listen port\n"
        "  -r <host:port>  Remote target address (e.g., 10.0.0.1:8080)\n"
        "  -k <hex>        PSK as hex string (min 16 bytes = 32 hex chars)\n"
        "  -f <file>       PSK from file (recommended: chmod 400)\n"
        "\n"
        "Options:\n"
        "  -C <file>       Config file (key=value format; CLI args override)\n"
        "  -m <mode>       'server' (default) or 'client'\n"
        "  -t <sec>        Handshake timeout in seconds (default: 5)\n"
        "  -c <max>        Max concurrent connections (default: 32)\n"
        "  -K <sec>        Keepalive interval in seconds (default: 0)\n"
        "  -T <name>       TUN mode: create virtual NIC (e.g., -T tun0)\n"
        "  -I <ip>         TUN IP address (e.g., -I 10.0.0.1)\n"
        "  -N <mask>       TUN netmask (default: 255.255.255.0)\n"
        "  -R <net>        TUN route (e.g., -R 10.0.0.0/24)\n"
        "  -W <iface>      WAN interface for NAT (default: eth0)\n"
        "  -P <file>       Asymmetric mode: private key file (32 bytes)\n"
        "  -Q <file>       Asymmetric mode: peer public key file (32 bytes)\n"
        "  -v              Verbose output (DEBUG level logging)\n"
        "  -h              Show this help\n"
        "\n"
        "Examples:\n"
        "  # Generate PSK:\n"
        "  dd if=/dev/urandom bs=16 count=1 of=/etc/aegis/psk.key\n"
        "  chmod 400 /etc/aegis/psk.key\n"
        "\n"
        "  # Server with config file:\n"
        "  %s -C /etc/aegis/server.conf -f /etc/aegis/psk.key\n"
        "\n"
        "  # Client:\n"
        "  %s -l 9000 -r server.example.com:9000 -f /etc/aegis/psk.key -m client\n"
        "\n",
        prog, prog, prog, prog);
}

/* ─── Server main loop ─────────────────────────────────────────── */

static int run_server(int listen_port, const char *remote_host, int remote_port,
                      const uint8_t *psk, size_t psk_len,
                      int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(listen_port);
    if (listen_fd < 0) return 1;

    log_info("server", "port %d → %s:%d (max %d connections)",
             listen_port, remote_host, remote_port, g_max_conns);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        /* ── Connection limit check ── */
        if (g_active_conns >= g_max_conns) {
            log_warn("server", "rejected: max connections (%d)", g_max_conns);
            close(client_fd);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        log_info("server", "#%d %s:%d",
                 (int)g_active_conns + 1, client_ip, ntohs(client_addr.sin_port));

        /* Set handshake timeout on client socket */
        set_socket_timeout(client_fd, hs_timeout);

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            /* ── Child process ── */
            close(listen_fd);
            signal(SIGCHLD, SIG_DFL);  /* restore default in child */

            session_keys_t keys;
            if (g_asym_mode
                ? (handshake_asymmetric_server(client_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
                : (handshake_server(client_fd, psk, (size_t)psk_len, hs_timeout, &keys) != 0)) {
                log_warn("server", "handshake failed");
                close(client_fd);
                _exit(1);
            }

            /* Key confirmation — proves both sides have matching session keys */
            if (handshake_key_confirm_server(client_fd, &keys, hs_timeout) != 0) {
                log_warn("server", "key confirmation failed");
                secure_memzero(&keys, sizeof(keys));
                close(client_fd);
                _exit(1);
            }

            int remote_fd = connect_to_host(remote_host, remote_port);
            if (remote_fd < 0) {
                close(client_fd);
                _exit(1);
            }

            /*
             * Server fd layout:
             *   fds[0] = remote_fd  ← plaintext (echo/target server)
             *   fds[1] = client_fd  ← encrypted frames from tunnel client
             */
            tunnel_t tun;
            tunnel_init(&tun, remote_fd, client_fd,
                        keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive;
            tun.rekey_sec     = 120;
            tun.psk           = psk;
            tun.psk_len       = (size_t)psk_len;

            int ret = tunnel_run(&tun);

            secure_memzero(&keys, sizeof(keys));
            close(remote_fd);
            close(client_fd);
            _exit(ret == 0 ? 0 : 1);
        }

        /* Parent: increment counter, close fd, continue */
        g_active_conns++;
        close(client_fd);
    }

    /* Wait for remaining children */
    while (waitpid(-1, NULL, 0) > 0) {}
    close(listen_fd);
    return 0;
}

/* ─── Client main loop ─────────────────────────────────────────── */

static int run_client(int local_port, const char *remote_host, int remote_port,
                      const uint8_t *psk, size_t psk_len,
                      int hs_timeout, int keepalive)
{
    int listen_fd = listen_on_port(local_port);
    if (listen_fd < 0) return 1;

    log_info("client", "port %d → %s:%d",
            local_port, remote_host, remote_port);

    while (g_running) {
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);

        int local_fd = accept(listen_fd,
                              (struct sockaddr *)&local_addr, &addr_len);
        if (local_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        if (g_active_conns >= g_max_conns) {
            close(local_fd);
            continue;
        }

        int tunnel_fd = connect_to_host(remote_host, remote_port);
        if (tunnel_fd < 0) {
            close(local_fd);
            continue;
        }

        set_socket_timeout(tunnel_fd, hs_timeout);

        session_keys_t keys;
        if (g_asym_mode
            ? (handshake_asymmetric_client(tunnel_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
            : (handshake_client(tunnel_fd, psk, (size_t)psk_len, hs_timeout, &keys) != 0)) {
            log_warn("client", "handshake failed");
            close(local_fd);
            close(tunnel_fd);
            continue;
        }

        /* Key confirmation */
        if (handshake_key_confirm_client(tunnel_fd, &keys, hs_timeout) != 0) {
            log_warn("client", "key confirmation failed");
            secure_memzero(&keys, sizeof(keys));
            close(local_fd);
            close(tunnel_fd);
            continue;
        }

        /*
         * Client fd layout:
         *   fds[0] = local_fd   ← plaintext from local user
         *   fds[1] = tunnel_fd  ← encrypted frames to/from tunnel server
         */
        tunnel_t tun;
        tunnel_init(&tun, local_fd, tunnel_fd,
                    keys.enc_key, keys.dec_key);
        tun.keepalive_sec = keepalive;
            tun.rekey_sec     = 120;
            tun.psk           = psk;
            tun.psk_len       = (size_t)psk_len;

        g_active_conns++;
        int ret = tunnel_run(&tun);
        g_active_conns--;

        secure_memzero(&keys, sizeof(keys));
        close(local_fd);
        close(tunnel_fd);

        if (ret != 0) {
            log_error("client", "tunnel error");
        }
    }

    close(listen_fd);
    return 0;
}

/* ════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    int  listen_port     = 0;
    char *remote_str     = NULL;
    char *psk_hex        = NULL;
    char *psk_file       = NULL;
    char *privkey_file   = NULL;
    char *peerkey_file   = NULL;
    char *config_file    = NULL;
    const char *mode     = "server";
    int  keepalive       = 0;
    int  hs_timeout      = DEFAULT_HS_TIMEOUT;
    int  tun_mode        = 0;
    char tun_name[16]    = "tun0";
    char tun_ip[32]      = "";
    char tun_netmask[32] = "255.255.255.0";
    char tun_route[64]   = "";
    char tun_nat_if[16]  = "eth0";  /* WAN interface for NAT */

    g_max_conns = DEFAULT_MAX_CONN;

    /* ── Parse arguments ── */
    int opt;
    while ((opt = getopt(argc, argv, "l:r:k:f:C:m:t:c:K:T:I:N:R:W:P:Q:vh")) != -1) {
        switch (opt) {
        case 'l': listen_port = atoi(optarg);           break;
        case 'r': remote_str  = optarg;                break;
        case 'k': psk_hex     = optarg;                break;
        case 'f': psk_file    = optarg;                break;
        case 'm': mode        = optarg;                break;
        case 't': hs_timeout  = atoi(optarg);           break;
        case 'c': g_max_conns = atoi(optarg);           break;
        case 'K': keepalive   = atoi(optarg);           break;
        case 'P': privkey_file = optarg; g_asym_mode=1;  break;
        case 'Q': peerkey_file = optarg; g_asym_mode=1;  break;
        case 'C': config_file = optarg;                break;
        case 'T': tun_mode    = 1;
                  strncpy(tun_name, optarg, sizeof(tun_name)-1); break;
        case 'I': strncpy(tun_ip, optarg, sizeof(tun_ip)-1);     break;
        case 'N': strncpy(tun_netmask, optarg, sizeof(tun_netmask)-1); break;
        case 'R': strncpy(tun_route, optarg, sizeof(tun_route)-1);   break;
        case 'W': strncpy(tun_nat_if, optarg, sizeof(tun_nat_if)-1); break;
        case 'v': log_set_level(LOG_DEBUG);            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* ── Load config file (CLI args take precedence) ── */
    if (config_file) {
        config_t cfg;
        if (config_load(&cfg, config_file) == 0) {
            if (!listen_port) listen_port = config_get_int(&cfg, "LISTEN_PORT", 0);
            if (!remote_str) {
                const char *v = config_get(&cfg, "REMOTE_ADDR");
                if (v) remote_str = strdup(v);
            }
            if (!psk_file) {
                const char *v = config_get(&cfg, "PSK_FILE");
                if (v) psk_file = strdup(v);
            }
            {
                const char *v = config_get(&cfg, "MODE");
                if (v) {
                    while (*v == ' ' || *v == '\t') v++;
                    if (strcmp(v, "client") == 0) mode = "client";
                }
            }
            if (hs_timeout == DEFAULT_HS_TIMEOUT)
                hs_timeout = config_get_int(&cfg, "HS_TIMEOUT", hs_timeout);
            if (g_max_conns == DEFAULT_MAX_CONN)
                g_max_conns = config_get_int(&cfg, "MAX_CONNS", g_max_conns);
            if (keepalive == 0)
                keepalive = config_get_int(&cfg, "KEEPALIVE", 0);

            /* TUN settings */
            if (!tun_mode) {
                const char *v = config_get(&cfg, "TUN_MODE");
                if (v && (strcmp(v, "1") == 0 || strcmp(v, "yes") == 0))
                    tun_mode = 1;
            }
            if (strcmp(tun_name, "tun0") == 0) {
                const char *v = config_get(&cfg, "TUN_NAME");
                if (v) strncpy(tun_name, v, sizeof(tun_name)-1);
            }
            if (!tun_ip[0]) {
                const char *v = config_get(&cfg, "TUN_IP");
                if (v) strncpy(tun_ip, v, sizeof(tun_ip)-1);
            }
            if (strcmp(tun_netmask, "255.255.255.0") == 0) {
                const char *v = config_get(&cfg, "TUN_NETMASK");
                if (v) strncpy(tun_netmask, v, sizeof(tun_netmask)-1);
            }
            if (!tun_route[0]) {
                const char *v = config_get(&cfg, "TUN_ROUTE");
                if (v) strncpy(tun_route, v, sizeof(tun_route)-1);
            }
            {
                const char *v = config_get(&cfg, "TUN_NAT_IF");
                if (v) strncpy(tun_nat_if, v, sizeof(tun_nat_if)-1);
            }
            config_free(&cfg);
            log_info("main", "loaded config from %s", config_file);
        }
    }

    /* Validate */
    if (listen_port <= 0 || !remote_str) {
        fprintf(stderr, "Error: -l and -r are required\n\n");
        usage(argv[0]);
        return 1;
    }
    /* Asymmetric mode requires -P and -Q, not a PSK */
    if (!g_asym_mode && !psk_hex && !psk_file) {
        fprintf(stderr, "Error: either (-k or -f) for PSK mode, or (-P and -Q) for asymmetric mode\n\n");
        usage(argv[0]);
        return 1;
    }
    if (g_asym_mode && (!privkey_file || !peerkey_file)) {
        fprintf(stderr, "Error: asymmetric mode requires both -P <private.key> and -Q <peer.pub>\n");
        return 1;
    }
    if (psk_hex && psk_file) {
        fprintf(stderr, "Error: use only one of -k or -f, not both\n");
        return 1;
    }
    if (strcmp(mode, "server") != 0 && strcmp(mode, "client") != 0) {
        fprintf(stderr, "Error: mode must be 'server' or 'client'\n");
        return 1;
    }
    if (hs_timeout < 1 || hs_timeout > 300) {
        fprintf(stderr, "Error: timeout must be 1-300 seconds\n");
        return 1;
    }
    if (g_max_conns < 1 || g_max_conns > 1024) {
        fprintf(stderr, "Error: max connections must be 1-1024\n");
        return 1;
    }

    /* ── Load keys (PSK or asymmetric) ── */
    uint8_t psk[MAX_PSK_BYTES];
    int psk_len = 0;

    if (g_asym_mode) {
        if (keyfile_load_private(g_asym_priv, privkey_file) != 0) return 1;
        if (keyfile_load_public(g_asym_peer, peerkey_file) != 0) return 1;
        /* Generate a dummy PSK for re-keying and key confirmation */
        random_bytes(psk, 16); psk_len = 16;
    } else {
        if (psk_file) {
            psk_len = read_psk_file(psk, sizeof(psk), psk_file);
        } else {
            psk_len = parse_hex(psk, sizeof(psk), psk_hex);
        }
        if (psk_len < HANDSHAKE_PSK_MIN_LEN) {
            fprintf(stderr, "Error: PSK must be at least %d bytes\n",
                    HANDSHAKE_PSK_MIN_LEN);
            return 1;
        }
    }

    /* ── Parse remote address ── */
    char remote_host[MAX_HOST_LEN];
    int  remote_port;
    char *host_ptr = NULL;
    char *addr_dup = strdup(remote_str);
    if (!addr_dup) { perror("strdup"); return 1; }

    if (parse_host_port(addr_dup, &host_ptr, &remote_port) != 0) {
        fprintf(stderr, "Error: invalid address '%s' (expected host:port)\n",
                remote_str);
        free(addr_dup);
        return 1;
    }
    strncpy(remote_host, host_ptr, sizeof(remote_host) - 1);
    remote_host[sizeof(remote_host) - 1] = '\0';
    memset(addr_dup, 0, strlen(addr_dup));  /* erase the copy */
    free(addr_dup);

    /* ── Install signal handlers ── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    /* ── TUN setup (if enabled) ── */
    int tun_fd = -1;
    if (tun_mode) {
        tun_fd = tun_create(tun_name);
        if (tun_fd < 0) {
            fprintf(stderr, "Error: TUN device creation failed (need root + 'modprobe tun')\n");
            secure_memzero(psk, sizeof(psk));
            return 1;
        }
        if (tun_ip[0]) {
            tun_set_ip(tun_name, tun_ip, tun_netmask);
        }
        tun_up(tun_name);
        if (tun_route[0]) {
            tun_add_route(tun_route, tun_name);
        }
        /* VPN gateway setup (server typically needs NAT + forwarding) */
        if (strcmp(mode, "server") == 0) {
            tun_enable_forwarding();
            tun_set_nat(tun_route[0] ? tun_route : "10.0.0.0/24",
                        tun_nat_if);
            tun_allow_forward(tun_name);
        }
    }

    /* ── Run ── */
    int ret;
    if (tun_mode) {
        /* TUN VPN mode: raw IP tunnel */
        if (strcmp(mode, "server") == 0) {
            int listen_fd = listen_on_port(listen_port);
            if (listen_fd < 0) { secure_memzero(psk, sizeof(psk)); return 1; }
            log_info("tun-server", "%s (%s/%s) listening on :%d",
                     tun_name, tun_ip[0] ? tun_ip : "dhcp", tun_netmask, listen_port);

            while (g_running) {
                struct sockaddr_in ca; socklen_t al = sizeof(ca);
                int client_fd = accept(listen_fd, (struct sockaddr *)&ca, &al);
                if (client_fd < 0) { if (errno == EINTR) continue; break; }
                if (g_active_conns >= g_max_conns) { close(client_fd); continue; }

                char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                log_info("tun-server", "client %s:%d", ip, ntohs(ca.sin_port));

                pid_t pid = fork();
                if (pid < 0) { close(client_fd); continue; }
                if (pid == 0) {
                    close(listen_fd);
                    session_keys_t keys;
                    if (g_asym_mode
                        ? (handshake_asymmetric_server(client_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
                        : (handshake_server(client_fd, psk, (size_t)psk_len, hs_timeout, &keys) != 0)) {
                        log_warn("tun-server", "handshake failed");
                        close(client_fd); _exit(1);
                    }
                    tunnel_t tun; tunnel_init(&tun, tun_fd, client_fd, keys.enc_key, keys.dec_key);
                    tun.keepalive_sec = keepalive;
                    tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = (size_t)psk_len;
                    int r = tunnel_run(&tun);
                    secure_memzero(&keys, sizeof(keys));
                    close(client_fd); _exit(r == 0 ? 0 : 1);
                }
                g_active_conns++; close(client_fd);
            }
            close(listen_fd);
            ret = 0;
        } else {
            int tunnel_fd = connect_to_host(remote_host, remote_port);
            if (tunnel_fd < 0) { secure_memzero(psk, sizeof(psk)); return 1; }
            log_info("tun-client", "%s (%s/%s) → %s:%d",
                     tun_name, tun_ip[0] ? tun_ip : "dhcp", tun_netmask,
                     remote_host, remote_port);

            session_keys_t keys;
            if (g_asym_mode
                ? (handshake_asymmetric_client(tunnel_fd, g_asym_priv, g_asym_peer, hs_timeout, &keys) != 0)
                : (handshake_client(tunnel_fd, psk, (size_t)psk_len, hs_timeout, &keys) != 0)) {
                log_warn("tun-client", "handshake failed");
                close(tunnel_fd); secure_memzero(psk, sizeof(psk)); return 1;
            }
            tunnel_t tun; tunnel_init(&tun, tun_fd, tunnel_fd, keys.enc_key, keys.dec_key);
            tun.keepalive_sec = keepalive;
            tun.rekey_sec = 120; tun.psk = psk; tun.psk_len = (size_t)psk_len;
            ret = tunnel_run(&tun);
            secure_memzero(&keys, sizeof(keys));
            close(tunnel_fd);
        }
    } else if (strcmp(mode, "server") == 0) {
        ret = run_server(listen_port, remote_host, remote_port,
                         psk, (size_t)psk_len, hs_timeout, keepalive);
    } else {
        ret = run_client(listen_port, remote_host, remote_port,
                         psk, (size_t)psk_len, hs_timeout, keepalive);
    }

    if (tun_fd >= 0) close(tun_fd);
    secure_memzero(psk, sizeof(psk));
    return ret;
}
