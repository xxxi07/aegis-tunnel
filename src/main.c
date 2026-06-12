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
#include "util/iniconfig.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
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
int   g_peer_count = 0;

static void sig_handler(int sig)   { (void)sig; g_running = 0; }
static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) g_active_conns--;
}

/* Get real user's home directory, even when running under sudo. */
static const char *get_real_home(void)
{
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user && sudo_user[0]) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw && pw->pw_dir) return pw->pw_dir;
    }
    const char *home = getenv("HOME");
    return home ? home : "/tmp";
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
int connect_to_host(const char *host, int port, int fwmark) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) { perror("socket"); return -1; }
    /* Set fwmark BEFORE connect so the TCP SYN bypasses TUN routes */
    if (fwmark > 0) setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark));
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
        "Usage: %s -c <config.conf>  (WireGuard-style, one file)\n"
        "       %s -r <host:port> [options]\n"
        "\n"
        "AEGIS-Tunnel -- Lightweight encrypted tunnel using AEGIS-128 AEAD\n"
        "\n"
        "Commands (recommended workflow):\n"
        "  keygen                         Generate keys + aegis.conf\n"
        "  peer add <name> <hex|file>     Add peer's public key\n"
        "  create tun -server|-client      Generate TUN config from aegis.conf\n"
        "  start tun -server|-client       Start TUN VPN from config\n"
        "  tun down [name]                Remove TUN device + iptables rules\n"
        "  peer list                      List known peers\n"
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

/* ─── Subcommands ─────────────────────────────────────────────── */
static int cmd_keygen(void) {
    const char *home = get_real_home();
    char dir[512]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    mkdir(dir, 0700);

    /* Generate keypair */
    char priv[520], pub[520];
    snprintf(priv, sizeof(priv), "%s/private.key", dir);
    snprintf(pub, sizeof(pub), "%s/public.key", dir);
    if (keyfile_generate(priv, pub) != 0) return 1;

    /* Show public key */
    printf("Public key (send to peer):\n  ");
    char hex[65] = "";
    FILE *f = fopen(pub, "r");
    if (f) { size_t nr = fread(hex, 1, 64, f); hex[nr] = '\0'; fclose(f); printf("%s\n", hex); }

    /* Clear old config files and regenerate aegis.conf */
    unlink("aegis.conf");
    unlink("aegis-server.conf");
    unlink("aegis-client.conf");

    {
        FILE *cf = fopen("aegis.conf", "w");
        if (cf) {
            fprintf(cf,
                "[Interface]\n"
                "PrivateKey = ~/.aegis-tunnel/private.key\n"
                "PublicKey = %s\n"
                "Port = 9000\n\n"
                "[Tunnel]\n"
                "Keepalive = 30\n"
                "NATInterface = eth0\n",
                hex);
            fclose(cf);
            printf("\nConfig: aegis.conf\n");
        }
    }

    printf("\nNext: get peer's public key, then:\n");
    printf("  aegis-tunnel peer add <name> <peer-hex-key>\n");
    return 0;
}
static int cmd_peer_add(const char *host, const char *hex_or_file) {
    const char *home = get_real_home();
    char dir[520], peer_dir[520], path[520];
    snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    snprintf(peer_dir, sizeof(peer_dir), "%s/peers", dir);
    mkdir(dir, 0700); mkdir(peer_dir, 0700);
    snprintf(path, sizeof(path), "%s/%s.pub", peer_dir, host);

    /* If hex_or_file looks like a file path, copy it; otherwise write as hex */
    if (strchr(hex_or_file, '/') || strchr(hex_or_file, '.')) {
        /* File path: copy contents */
        FILE *src = fopen(hex_or_file, "r");
        if (!src) { fprintf(stderr, "Cannot open %s\n", hex_or_file); return 1; }
        FILE *dst = fopen(path, "w");
        if (!dst) { fclose(src); return 1; }
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
        fclose(src); fclose(dst);
    } else {
        /* Hex string: validate and write */
        size_t hlen = strlen(hex_or_file);
        if (hlen != 64) {
            fprintf(stderr, "Error: hex key must be 64 characters (got %zu)\n", hlen);
            return 1;
        }
        FILE *f = fopen(path, "w");
        if (!f) return 1;
        fprintf(f, "%s\n", hex_or_file);
        fclose(f);
    }
    printf("Peer '%s' added.\n", host);

    /* Update/create config file in current directory */
    {
        char cfg[520] = "aegis.conf";

        /* Create config if it doesn't exist yet */
        if (access(cfg, F_OK) != 0) {
            FILE *cf = fopen(cfg, "w");
            if (cf) {
                /* Read our public key for the Interface section */
                char our_pub[65] = "";
                {
                    char pub_path[520];
                    snprintf(pub_path, sizeof(pub_path), "%s/public.key", dir);
                    FILE *pf = fopen(pub_path, "r");
                    if (pf) { size_t nr = fread(our_pub, 1, 64, pf); our_pub[nr] = '\0'; fclose(pf); }
                }
                fprintf(cf,
                    "[Interface]\n"
                    "PrivateKey = ~/.aegis-tunnel/private.key\n"
                    "PublicKey = %s\n"
                    "Port = 9000\n\n"
                    "[Tunnel]\n"
                    "Keepalive = 30\n"
                    "NATInterface = eth0\n",
                    our_pub);
                fclose(cf);
            }
        }

        /* Get peer hex key */
        char peerfile[520], hx[65] = "";
        snprintf(peerfile, sizeof(peerfile), "%s/%s.pub", peer_dir, host);
        FILE *pf = fopen(peerfile, "r");
        if (pf) { size_t nr = fread(hx, 1, 64, pf); hx[nr]='\0';
                  for (int i=(int)nr-1; i>=0 && (hx[i]=='\n'||hx[i]=='\r'); i--) hx[i]='\0';
                  fclose(pf); }

        /* cfg is already set to the right path from above */
        if (hx[0]) {
            FILE *in = fopen(cfg, "r");
            int found = 0;
            if (in) {
                /* Check if this hex already exists in any [Peer] */
                char line[512];
                while (fgets(line, sizeof(line), in))
                    if (strstr(line, "PublicKey") && strstr(line, hx)) found = 1;
                fclose(in);
            }
            if (!found) {
                /* Append new [Peer] section */
                FILE *out = fopen(cfg, "a");  /* append mode */
                if (out) {
                    fprintf(out, "\n[Peer]\n");
                    fprintf(out, "PublicKey = %s\n", hx);
                    fprintf(out, "Endpoint = %s\n", host);
                    fclose(out);
                    printf("Config updated: aegis.conf (+[Peer])\n");
                }
            } else {
                printf("Already in config\n");
            }
        }
    }
    return 0;
}
static int cmd_peer_list(void) {
    const char *home = get_real_home();
    char dir[520]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel/peers", home);
    DIR *d = opendir(dir);
    if (!d) { printf("No peers configured yet.\n"); return 0; }
    printf("Known peers:\n");
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        size_t len = strlen(e->d_name);
        if (len > 4 && !strcmp(e->d_name + len - 4, ".pub"))
            printf("  %.*s\n", (int)(len - 4), e->d_name);
    }
    closedir(d);
    return 0;
}
static int cmd_status(void) {
    const char *home = get_real_home();
    char dir[520]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    printf("Key storage: %s\n", dir);
    struct stat st;
    if (stat(dir, &st) == 0) {
        char path[520];
        snprintf(path, sizeof(path), "%s/private.key", dir);
        printf("  Private key: %s (%s)\n", path,
               (access(path, F_OK) == 0) ? "exists" : "missing");
        snprintf(path, sizeof(path), "%s/public.key", dir);
        printf("  Public key:  %s (%s)\n", path,
               (access(path, F_OK) == 0) ? "exists" : "missing");
    } else {
        printf("  (not yet created — run 'aegis-tunnel keygen')\n");
    }
    cmd_peer_list();
    return 0;
}
static int cmd_tun_down(const char *name) {
    if (!name) name = "tun0";
    /* Flush TUN routing table and clean policy rule */
    system("ip route flush table 51820 2>/dev/null");
    system("ip rule del not fwmark 51820 table 51820 2>/dev/null");
    system("ip rule del not fwmark 51820 table main 2>/dev/null");   /* legacy */
    system("ip rule del fwmark 51820 table main 2>/dev/null");       /* legacy */
    /* Delete TUN device */
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name);
    system(cmd);
    /* Clean iptables */
    system("iptables -t nat -F POSTROUTING 2>/dev/null");
    system("iptables -F FORWARD 2>/dev/null");
    printf("TUN %s removed, routes and iptables cleared.\n", name);
    return 0;
}

/*
 * Create a TUN-specific config from aegis.conf.
 *   is_server: 1 → aegis-server.conf, 0 → aegis-client.conf
 *
 * Reads base aegis.conf, adds TUN-specific settings,
 * writes the result to aegis-server.conf or aegis-client.conf.
 */
static int cmd_create_tun(int is_server) {
    const char *src = "aegis.conf";
    const char *dst = is_server ? "aegis-server.conf" : "aegis-client.conf";

    if (access(src, F_OK) != 0) {
        fprintf(stderr, "Error: %s not found. Run 'aegis-tunnel keygen' first.\n", src);
        return 1;
    }

    iniconf_t icfg;
    if (iniconf_load(&icfg, src) != 0) {
        fprintf(stderr, "Error: cannot parse %s\n", src);
        return 1;
    }

    /* Read base fields from aegis.conf */
    const char *privkey  = iniconf_get(&icfg, "Interface", "PrivateKey");
    const char *pubkey   = iniconf_get(&icfg, "Interface", "PublicKey");
    const char *port     = iniconf_get(&icfg, "Interface", "Port");
    const char *nat_if   = iniconf_get(&icfg, "Tunnel", "NATInterface");
    const char *keepalive = iniconf_get(&icfg, "Tunnel", "Keepalive");

    /* Read our public key from the key file (for display in config) */
    char pubkey_hex[65] = "";
    {
        const char *home = get_real_home();
        char pub_path[520];
        snprintf(pub_path, sizeof(pub_path), "%s/.aegis-tunnel/public.key", home);
        FILE *f = fopen(pub_path, "r");
        if (f) {
            size_t n = fread(pubkey_hex, 1, 64, f);
            pubkey_hex[n] = '\0';
            fclose(f);
        }
    }

    FILE *out = fopen(dst, "w");
    if (!out) { perror(dst); iniconf_free(&icfg); return 1; }

    fprintf(out, "# AEGIS-Tunnel TUN %s config (generated from %s)\n\n",
            is_server ? "server" : "client", src);

    /* ── [Interface] ── */
    fprintf(out, "[Interface]\n");
    fprintf(out, "PrivateKey = %s\n", privkey ? privkey : "~/.aegis-tunnel/private.key");
    if (pubkey_hex[0])
        fprintf(out, "PublicKey = %s\n", pubkey_hex);
    else if (pubkey)
        fprintf(out, "PublicKey = %s\n", pubkey);
    fprintf(out, "Mode = %s\n", is_server ? "server" : "client");

    if (is_server) {
        fprintf(out, "Address = 10.0.0.1/24\n");
        fprintf(out, "ListenPort = %s\n", port ? port : "9000");
        fprintf(out, "# PostUp = iptables -A FORWARD -i %%i -j ACCEPT;"
                     " iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o %s -j MASQUERADE\n",
                nat_if ? nat_if : "eth0");
        fprintf(out, "# PostDown = iptables -D FORWARD -i %%i -j ACCEPT;"
                     " iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o %s -j MASQUERADE\n",
                nat_if ? nat_if : "eth0");
    } else {
        fprintf(out, "Address = 10.0.0.2/24\n");
    }
    fprintf(out, "\n");

    /* ── [Peer] sections (iterate all peers from base config) ── */
    {
        int peer_idx = 0;
        while (1) {
            const char *pk = iniconf_get_indexed(&icfg, "Peer", peer_idx, "PublicKey");
            if (!pk) break;
            const char *ep = iniconf_get_indexed(&icfg, "Peer", peer_idx, "Endpoint");

            fprintf(out, "[Peer]\n");
            fprintf(out, "PublicKey = %s\n", pk);

            if (is_server) {
                fprintf(out, "AllowedIPs = 10.0.0.0/24\n");
                if (ep) fprintf(out, "# Endpoint = %s\n", ep);
            } else {
                /* Client: only first peer gets Endpoint */
                if (peer_idx == 0) {
                    char ep_buf[320];
                    if (ep) snprintf(ep_buf, sizeof(ep_buf), "%s", ep);
                    else    snprintf(ep_buf, sizeof(ep_buf), "server.com:9000");
                    if (!strrchr(ep_buf, ':')) {
                        size_t el = strlen(ep_buf);
                        snprintf(ep_buf + el, sizeof(ep_buf) - el, ":9000");
                    }
                    fprintf(out, "Endpoint = %s\n", ep_buf);
                }
                fprintf(out, "AllowedIPs = 0.0.0.0/0\n");
                fprintf(out, "PersistentKeepalive = %s\n", keepalive ? keepalive : "25");
            }
            fprintf(out, "\n");
            peer_idx++;
        }
        if (peer_idx == 0) {
            /* No peers in base config — fallback placeholder */
            fprintf(out, "[Peer]\n");
            fprintf(out, "PublicKey = <peer-public-key>\n");
            if (is_server)
                fprintf(out, "AllowedIPs = 10.0.0.0/24\n");
            else {
                fprintf(out, "Endpoint = server.com:9000\n");
                fprintf(out, "AllowedIPs = 0.0.0.0/0\n");
                fprintf(out, "PersistentKeepalive = %s\n", keepalive ? keepalive : "25");
            }
            fprintf(out, "\n");
        }
    }

    /* ── [Tunnel] ── */
    fprintf(out, "[Tunnel]\n");
    fprintf(out, "Keepalive = %s\n", keepalive ? keepalive : "30");
    fprintf(out, "NATInterface = %s\n", nat_if ? nat_if : "eth0");
    fprintf(out, "Timeout = 10\n");
    fprintf(out, "MaxConnections = 64\n");

    fclose(out);
    iniconf_free(&icfg);

    printf("TUN %s config written to %s\n", is_server ? "server" : "client", dst);
    printf("\nReview and edit %s if needed, then:\n", dst);
    printf("  sudo ./aegis-tunnel start tun -%s\n", is_server ? "server" : "client");
    return 0;
}

int main(int argc, char **argv) {
    /* Subcommands: aegis-tunnel keygen | peer add <host> <hex> | peer list */
    int  start_tun_force = 0;  /* 1=server, 2=client — set by 'start tun' subcommand */
    if (argc >= 2) {
        if (!strcmp(argv[1], "keygen"))    return cmd_keygen();
        if (!strcmp(argv[1], "status"))    return cmd_status();
        if (!strcmp(argv[1], "tun") && argc >= 3 && !strcmp(argv[2], "down"))
                                           return cmd_tun_down(argc >= 4 ? argv[3] : "tun0");
        if (!strcmp(argv[1], "peer") && argc >= 3) {
            if (!strcmp(argv[2], "list"))  return cmd_peer_list();
            if (!strcmp(argv[2], "add") && argc >= 5) return cmd_peer_add(argv[3], argv[4]);
            fprintf(stderr, "Usage: %s peer add <host> <hex-or-file>\n", argv[0]);
            fprintf(stderr, "       %s peer list\n", argv[0]);
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
    }

    int  listen_port = 9000;  /* default port */
    char *remote_str = NULL, *config_file = NULL;
    char *privkey_file = NULL, *peerkey_file = NULL;
    const char *mode = "server";
    int  keepalive = 0, hs_timeout = DEFAULT_HS_TIMEOUT;
    int  tun_mode = 0;
    char tun_name[16] = "tun0", tun_ip[32] = "", tun_netmask[32] = "255.255.255.0";
    char tun_route[64] = "", tun_nat_if[16] = "eth0";
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
                      uint32_t ip_n;
                      sscanf(tun_ip, "%u.%u.%u.%u",
                             (unsigned *)&ip_n, (unsigned *)&ip_n,
                             (unsigned *)&ip_n, (unsigned *)&ip_n);
                      /* Actually need octets. Simpler: just use the first 3 octets */
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
        /* Auto-detect config file if not explicitly given */
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
                /* Prefer ListenPort (TUN-specific), fallback to Port */
                int lp = iniconf_get_int(&icfg, "Interface", "ListenPort", 0);
                if (lp > 0) listen_port = lp;
                else listen_port = iniconf_get_int(&icfg, "Interface", "Port", listen_port);
            }
            /* PostUp / PostDown (WireGuard-style, %i = interface name) */
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
                    /* In server mode, Endpoint can be 0.0.0.0:0 (meaning no forwarding) */
                    if (strcmp(v, "0.0.0.0:0") == 0) {
                        remote_str = NULL; /* TUN server, no backend */
                    } else {
                        remote_str = strdup(v);
                    }
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
                        char *exp = (char*)malloc(strlen(home) + strlen(v) + 1);
                        sprintf(exp, "%s%s", home, v + 1);
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
                            g_peer_count = pi + 1;
                        }
                    }
                    pi++;
                }
                if (g_peer_count > 0)
                    log_info("main", "%d peer(s) from config", g_peer_count);
                /* If no peers in config → auto-detect from ~/.aegis-tunnel/peers/ later */
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
                        /* Auto-derive route only if AllowedIPs not already set */
                        if (!tun_route[0]) {
                            char *dot = strrchr(tun_ip, '.');
                            if (dot) { *dot = '\0'; snprintf(tun_route, 63, "%s.0/%d", tun_ip, px); *dot = '.'; }
                        }
                    }
                }
            }
            /* PersistentKeepalive (client-side, in seconds) */
            if (keepalive == 0) {
                keepalive = iniconf_get_int(&icfg, "Peer", "PersistentKeepalive", 0);
            }
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

    /* ── Legacy key=value config fallback ── */
    if (config_file) {
        config_t cfg;
        if (config_load(&cfg, config_file) == 0) {
            if (listen_port == 9000) listen_port = config_get_int(&cfg, "LISTEN_PORT", 9000);
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

    if (listen_port <= 0) { fprintf(stderr, "Error: invalid port\n"); return 1; }
    if (!remote_str && !tun_mode && strcmp(mode, "server")) {
        fprintf(stderr, "Error: -r <host:port> is required\n"); usage(argv[0]); return 1; }
    if (strcmp(mode,"server") && strcmp(mode,"client")) { fprintf(stderr, "Error: mode must be server or client\n"); return 1; }


    /* Rekey bootstrap (random key for re-keying) */
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
    char key_dir[512], default_priv[520];
    { const char *home = get_real_home();
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
            if (parse_hex(g_asym_peers[0], 32, peerkey_file) != 32) {
                fprintf(stderr, "Error: -Q hex key must be 64 hex characters\n");
                return 1;
            }
            g_peer_count = 1;
            log_info("main", "peer key from hex string");
        } else {
            /* File path */
            if (keyfile_load_public(g_asym_peers[0], peerkey_file) != 0) return 1;
            g_peer_count = 1;
            log_info("main", "peer key from file: %s", peerkey_file);
        }
    } else if (g_peer_count == 0) {
        /* No peer from config or -Q → auto-detect from ~/.aegis-tunnel/peers/ */
        char peer_dir[520];
        snprintf(peer_dir, sizeof(peer_dir), "%s/peers", key_dir);
        mkdir(peer_dir, 0700);

        /* Count .pub files in peers/ */
        int peer_count = 0;
        char found_peer[520] = "";
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

        if (peer_count == 1) {
            /* Exactly one peer → use it */
            if (keyfile_load_public(g_asym_peers[0], found_peer) != 0) return 1;
            log_info("main", "using peer key: %s", found_peer);
        } else if (peer_count > 1) {
            /* Multiple peers → use the first one as default
             * (like SSH authorized_keys: any known peer can connect.
             *  Use -Q to restrict to a specific peer.) */
            if (keyfile_load_public(g_asym_peers[0], found_peer) != 0) return 1;
            log_info("main", "%d peers found, using first: %s", peer_count, found_peer);
        } else {
            /* No peer key — print our public key */
            fprintf(stderr, "\n═══ No peer key found ═══\n");
            fprintf(stderr, "Your public key (send to peer):\n  ");
            {
                char pub_path[520];
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
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;  /* no SA_RESTART: allow accept() to be interrupted */
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = sigchld_handler; sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int ret;
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
