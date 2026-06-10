/*
 * main.c — AEGIS-Tunnel entry point (argument parsing + dispatch)
 *
 * Asymmetric handshake only. Use aegis-tunnel-keygen to create keys.
 */
#include "main.h"
#include "protocol/handshake.h"
#include "protocol/keyfile.h"
#include "tunnel/tun.h"
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
uint8_t g_asym_peer[32];

static void sig_handler(int sig)   { (void)sig; g_running = 0; }
static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) g_active_conns--;
}

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
int connect_to_host(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) { perror("socket"); return -1; }
    struct hostent *he = gethostbyname(host);
    if (!he) { fprintf(stderr, "Error: cannot resolve '%s'\n", host); close(fd); return -1; }
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; memcpy(&a.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("connect"); close(fd); return -1; }
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
void set_socket_timeout(int fd, int seconds) {
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -l <port> -r <host:port> -P <priv.key> -Q <peer.pub> [options]\n"
        "       %s -C <config.conf>  (read all settings from file)\n"
        "\n"
        "AEGIS-Tunnel -- Lightweight encrypted tunnel using AEGIS-128 AEAD\n"
        "\n"
        "Required:\n"
        "  -l <port>       Local listen port\n"
        "  -r <host:port>  Remote target address\n"
        "\n"
        "Keys (~/.aegis-tunnel/, auto-generated):\n"
        "  First run: keys generated, public key printed\n"
        "  Then paste peer's hex public key with -Q <hex>\n"
        "  Or use -Q <file> to specify a peer key file\n"
        "\n"
        "Options:\n"
        "  -P <file>       Override private key path\n"
        "  -Q <hex|file>   Peer public key (64 hex chars = 32 bytes, or file path)\n"
        "  -C <file>       Config file\n"
        "  -m <mode>       'server' (default) or 'client'\n"
        "  -t <sec>        Handshake timeout (default: 5)\n"
        "  -c <max>        Max connections (default: 32)\n"
        "  -K <sec>        Keepalive interval (default: 0)\n"
        "  -T <name>       TUN mode: virtual NIC name\n"
        "  -I <ip>         TUN IP address\n"
        "  -N <mask>       TUN netmask (default: 255.255.255.0)\n"
        "  -R <net>        TUN route\n"
        "  -W <iface>      WAN interface for NAT (default: eth0)\n"
        "  -v              Verbose logging\n"
        "  -h              Show this help\n"
        "\n"
        "Setup:\n"
        "  1. Run: %s -l 9000 -r server:9000 (prints your public key)\n"
        "  2. Send your public key to peer, get theirs\n"
        "  3. Run: %s -l 9000 -r server:9000 -Q <peer-hex-key>\n"
        "\n"
        "Examples:\n"
        "  # Server: %s -l 9000 -r 127.0.0.1:8080\n"
        "  # Client: %s -l 9000 -r server:9000 -m client\n"
        "\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    int  listen_port = 0;
    char *remote_str = NULL, *config_file = NULL;
    char *privkey_file = NULL, *peerkey_file = NULL;
    const char *mode = "server";
    int  keepalive = 0, hs_timeout = DEFAULT_HS_TIMEOUT;
    int  tun_mode = 0;
    char tun_name[16] = "tun0", tun_ip[32] = "", tun_netmask[32] = "255.255.255.0";
    char tun_route[64] = "", tun_nat_if[16] = "eth0";

    int opt;
    while ((opt = getopt(argc, argv, "l:r:P:Q:C:m:t:c:K:T:I:N:R:W:vh")) != -1) {
        switch (opt) {
        case 'l': listen_port = atoi(optarg);           break;
        case 'r': remote_str  = optarg;                break;
        case 'P': privkey_file = optarg;               break;
        case 'Q': peerkey_file = optarg;               break;
        case 'C': config_file = optarg;                break;
        case 'm': mode        = optarg;                break;
        case 't': hs_timeout  = atoi(optarg);           break;
        case 'c': g_max_conns = atoi(optarg);           break;
        case 'K': keepalive   = atoi(optarg);           break;
        case 'T': tun_mode    = 1; strncpy(tun_name, optarg, 15);   break;
        case 'I': strncpy(tun_ip, optarg, 31);           break;
        case 'N': strncpy(tun_netmask, optarg, 31);      break;
        case 'R': strncpy(tun_route, optarg, 63);         break;
        case 'W': strncpy(tun_nat_if, optarg, 15);        break;
        case 'v': log_set_level(LOG_DEBUG);             break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (config_file) {  /* load config (CLI args override) */
        config_t cfg;
        if (config_load(&cfg, config_file) == 0) {
            if (!listen_port) listen_port = config_get_int(&cfg, "LISTEN_PORT", 0);
            if (!remote_str)  { const char *v = config_get(&cfg, "REMOTE_ADDR"); if (v) remote_str = strdup(v); }
            if (!privkey_file){ const char *v = config_get(&cfg, "PRIVATE_KEY"); if (v) privkey_file = strdup(v); }
            if (!peerkey_file){ const char *v = config_get(&cfg, "PEER_KEY");    if (v) peerkey_file = strdup(v); }
            { const char *v = config_get(&cfg, "MODE"); if (v) { while(*v==' '||*v=='\t')v++; if(!strcmp(v,"client")) mode="client"; } }
            if (hs_timeout == DEFAULT_HS_TIMEOUT) hs_timeout = config_get_int(&cfg, "HS_TIMEOUT", hs_timeout);
            if (g_max_conns == DEFAULT_MAX_CONN)   g_max_conns  = config_get_int(&cfg, "MAX_CONNS", g_max_conns);
            if (keepalive == 0) keepalive = config_get_int(&cfg, "KEEPALIVE", 0);
            if (!tun_mode) { const char *v = config_get(&cfg, "TUN_MODE"); if (v && (!strcmp(v,"1")||!strcmp(v,"yes"))) tun_mode = 1; }
            if (!strcmp(tun_name,"tun0"))      { const char *v = config_get(&cfg, "TUN_NAME");    if (v) strncpy(tun_name, v, 15); }
            if (!tun_ip[0])                     { const char *v = config_get(&cfg, "TUN_IP");      if (v) strncpy(tun_ip, v, 31); }
            if (!strcmp(tun_netmask,"255.255.255.0")){ const char *v = config_get(&cfg, "TUN_NETMASK"); if (v) strncpy(tun_netmask, v, 31); }
            if (!tun_route[0])                  { const char *v = config_get(&cfg, "TUN_ROUTE");   if (v) strncpy(tun_route, v, 63); }
            { const char *v = config_get(&cfg, "TUN_NAT_IF"); if (v) strncpy(tun_nat_if, v, 15); }
            config_free(&cfg);
            log_info("main", "loaded config from %s", config_file);
        }
    }

    if (listen_port <= 0 || !remote_str) { fprintf(stderr, "Error: -l and -r required\n"); usage(argv[0]); return 1; }
    if (strcmp(mode,"server") && strcmp(mode,"client")) { fprintf(stderr, "Error: mode must be server or client\n"); return 1; }


    /* Rekey bootstrap (random key for re-keying) */
    uint8_t psk[MAX_PSK_BYTES]; random_bytes(psk, 16);
    size_t psk_len = 16;

    char remote_host[MAX_HOST_LEN]; int remote_port; char *hp = NULL;
    char *ac = strdup(remote_str); if (!ac) { perror("strdup"); return 1; }
    if (parse_host_port(ac, &hp, &remote_port) != 0) { fprintf(stderr, "Error: '%s' format: host:port\n", remote_str); free(ac); return 1; }
    strncpy(remote_host, hp, MAX_HOST_LEN-1); remote_host[MAX_HOST_LEN-1]='\0'; free(ac);

    /* Default key paths: ~/.aegis-tunnel/ */
    char key_dir[512], default_priv[520];
    { const char *home = getenv("HOME"); if (!home) home = "/tmp";
      snprintf(key_dir, sizeof(key_dir), "%s/.aegis-tunnel", home);
      mkdir(key_dir, 0700); }

    if (!privkey_file) {
        snprintf(default_priv, sizeof(default_priv), "%s/private.key", key_dir);
        if (access(default_priv, F_OK) != 0) {
            char pub_path[520];
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
            /* Hex string: parse directly */
            if (parse_hex(g_asym_peer, 32, peerkey_file) != 32) {
                fprintf(stderr, "Error: -Q hex key must be 64 hex characters\n");
                return 1;
            }
            log_info("main", "peer key from hex string");
        } else {
            /* File path */
            if (keyfile_load_public(g_asym_peer, peerkey_file) != 0) return 1;
            log_info("main", "peer key from file: %s", peerkey_file);
        }
    } else {
        /* Try default peer path */
        char peer_dir[520], default_peer[520];
        snprintf(peer_dir, sizeof(peer_dir), "%s/peers", key_dir);
        mkdir(peer_dir, 0700);
        snprintf(default_peer, sizeof(default_peer), "%s/peers/%s.pub", key_dir, remote_host);
        if (access(default_peer, F_OK) == 0) {
            if (keyfile_load_public(g_asym_peer, default_peer) != 0) return 1;
            log_info("main", "using peer key: %s", default_peer);
        } else {
            /* No peer key — print our public key and ask for theirs */
            fprintf(stderr, "\n═══ No peer key found ═══\n");
            fprintf(stderr, "Your public key (send this to peer):\n  ");
            {
                char pub_path[520];
                snprintf(pub_path, sizeof(pub_path), "%s/public.key", key_dir);
                uint8_t our_pub[32];
                if (keyfile_load_public(our_pub, pub_path) == 0) {
                    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", our_pub[i]);
                }
            }
            fprintf(stderr, "\n\nThen run again with peer's key:\n");
            fprintf(stderr, "  %s -l %d -r %s -Q <peer-hex-key>\n",
                    argv[0], listen_port, remote_str);
            return 1;
        }
    }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask); sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = sigchld_handler; sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int ret;
    if (tun_mode) {
        if (!strcmp(mode, "server"))
            ret = mode_tun_server(listen_port, tun_name, tun_ip, tun_netmask,
                                  tun_route[0]?tun_route:NULL, tun_nat_if,
                                  psk, psk_len, hs_timeout, keepalive);
        else
            ret = mode_tun_client(listen_port, remote_host, remote_port,
                                  tun_name, tun_ip, tun_netmask,
                                  tun_route[0]?tun_route:NULL,
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
