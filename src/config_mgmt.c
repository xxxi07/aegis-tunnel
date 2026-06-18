/*
 * config_mgmt.c — Configuration management subcommands
 *
 * Implements: keygen, peer add/delete/list, create tun,
 * tun down, status.  Extracted from main.c to keep it lean.
 */
#include "config_mgmt.h"
#include "protocol/keyfile.h"
#include "util/iniconfig.h"
#include "util/util.h"

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ─── System helpers ─────────────────────────────────────────────── */

const char *get_real_home(void)
{
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user && sudo_user[0]) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw && pw->pw_dir) return pw->pw_dir;
    }
    const char *home = getenv("HOME");
    return home ? home : "/tmp";
}

const char *detect_default_iface(void)
{
    static char iface[16] = "";
    if (iface[0]) return iface;

    FILE *fp = popen("ip route show default 2>/dev/null", "r");
    if (!fp) goto fallback;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { pclose(fp); goto fallback; }
    pclose(fp);

    char *dev = strstr(line, " dev ");
    if (dev) {
        dev += 5;
        char *end = dev;
        while (*end && *end != ' ' && *end != '\n') end++;
        size_t len = (size_t)(end - dev);
        if (len > 0 && len < 16) {
            memcpy(iface, dev, len);
            iface[len] = '\0';
            return iface;
        }
    }
fallback:
    strcpy(iface, "eth0");
    return iface;
}

/* ─── cmd_keygen ─────────────────────────────────────────────────── */

int cmd_keygen(void)
{
    const char *home = get_real_home();
    char dir[768]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    mkdir(dir, 0700);

    char priv[768], pub[768];
    snprintf(priv, sizeof(priv), "%s/private.key", dir);
    snprintf(pub, sizeof(pub), "%s/public.key", dir);
    if (keyfile_generate(priv, pub) != 0) return 1;

    printf("Public key (send to peer):\n  ");
    char hex[65] = "";
    FILE *f = fopen(pub, "r");
    if (f) { size_t nr = fread(hex, 1, 64, f); hex[nr] = '\0'; fclose(f); printf("%s\n", hex); }

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
                "NATInterface = %s\n",
                hex, detect_default_iface());
            fclose(cf);
            printf("\nConfig: aegis.conf\n");
        }
    }

    printf("\nNext: get peer's public key, then:\n");
    printf("  aegis-tunnel peer add <name> <peer-hex-key>\n");
    return 0;
}

/* ─── cmd_peer_add ───────────────────────────────────────────────── */

int cmd_peer_add(const char *host, const char *hex_or_file)
{
    const char *home = get_real_home();
    char dir[768], peer_dir[768], path[768];
    snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    snprintf(peer_dir, sizeof(peer_dir), "%s/peers", dir);
    mkdir(dir, 0700); mkdir(peer_dir, 0700);
    snprintf(path, sizeof(path), "%s/%s.pub", peer_dir, host);

    if (strchr(hex_or_file, '/') || strchr(hex_or_file, '.')) {
        FILE *src = fopen(hex_or_file, "r");
        if (!src) { fprintf(stderr, "Cannot open %s\n", hex_or_file); return 1; }
        FILE *dst = fopen(path, "w");
        if (!dst) { fclose(src); return 1; }
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
        fclose(src); fclose(dst);
    } else {
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
        char cfg[768] = "aegis.conf";

        if (access(cfg, F_OK) != 0) {
            FILE *cf = fopen(cfg, "w");
            if (cf) {
                char our_pub[65] = "";
                {
                    char pub_path[768];
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
                    "NATInterface = %s\n",
                    our_pub, detect_default_iface());
                fclose(cf);
            }
        }

        char peerfile[768], hx[65] = "";
        snprintf(peerfile, sizeof(peerfile), "%s/%s.pub", peer_dir, host);
        FILE *pf = fopen(peerfile, "r");
        if (pf) { size_t nr = fread(hx, 1, 64, pf); hx[nr]='\0';
                  for (int i=(int)nr-1; i>=0 && (hx[i]=='\n'||hx[i]=='\r'); i--) hx[i]='\0';
                  fclose(pf); }

        if (hx[0]) {
            FILE *in = fopen(cfg, "r");
            int found = 0;
            if (in) {
                char line[512];
                while (fgets(line, sizeof(line), in))
                    if (strstr(line, "PublicKey") && strstr(line, hx)) found = 1;
                fclose(in);
            }
            if (!found) {
                FILE *out = fopen(cfg, "a");
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

/* ─── cmd_peer_delete ────────────────────────────────────────────── */

int cmd_peer_delete(const char *name)
{
    const char *home = get_real_home();
    char peerfile[768];
    snprintf(peerfile, sizeof(peerfile), "%s/.aegis-tunnel/peers/%s.pub", home, name);

    char hx[65] = "";
    FILE *pf = fopen(peerfile, "r");
    if (pf) {
        size_t nr = fread(hx, 1, 64, pf); hx[nr] = '\0';
        for (int i = (int)nr - 1; i >= 0 && (hx[i] == '\n' || hx[i] == '\r'); i--) hx[i] = '\0';
        fclose(pf);
    }

    if (unlink(peerfile) != 0) {
        fprintf(stderr, "Peer '%s' not found.\n", name);
        return 1;
    }
    printf("Peer '%s' removed from key storage.\n", name);

    if (access("aegis.conf", F_OK) == 0) {
        FILE *in = fopen("aegis.conf", "r");
        if (!in) return 0;
        char tmp[768];
        snprintf(tmp, sizeof(tmp), "aegis.conf.%d", getpid());
        FILE *out = fopen(tmp, "w");
        if (!out) { fclose(in); return 0; }

        char line[512];
        int in_peer = 0, skip_peer = 0, wrote_peer = 0;
        while (fgets(line, sizeof(line), in)) {
            if (line[0] == '[') {
                if (in_peer && !skip_peer && !wrote_peer) {
                    fputs("[Peer]\n", out);
                }
                in_peer = 0; skip_peer = 0; wrote_peer = 0;
                if (strstr(line, "[Peer]")) {
                    in_peer = 1;
                } else {
                    fputs(line, out);
                }
                continue;
            }
            if (in_peer && hx[0] && strstr(line, "PublicKey") && strstr(line, hx))
                skip_peer = 1;
            if (skip_peer) continue;
            if (in_peer && !wrote_peer) {
                fputs("[Peer]\n", out);
                wrote_peer = 1;
            }
            fputs(line, out);
        }
        if (in_peer && !skip_peer && !wrote_peer) {
            fputs("[Peer]\n", out);
        }
        fclose(in); fclose(out);
        rename(tmp, "aegis.conf");
        printf("Config updated: aegis.conf (-[Peer])\n");
    }
    return 0;
}

/* ─── cmd_peer_list ──────────────────────────────────────────────── */

int cmd_peer_list(void)
{
    const char *home = get_real_home();
    char dir[768]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel/peers", home);
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

/* ─── cmd_status ─────────────────────────────────────────────────── */

int cmd_status(void)
{
    const char *home = get_real_home();
    char dir[768]; snprintf(dir, sizeof(dir), "%s/.aegis-tunnel", home);
    printf("Key storage: %s\n", dir);
    struct stat st;
    if (stat(dir, &st) == 0) {
        char path[768];
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

/* ─── cmd_tun_down ───────────────────────────────────────────────── */

int cmd_tun_down(const char *name)
{
    if (!name) name = "tun0";
    system("ip route flush table 51820 2>/dev/null");
    system("ip rule del not fwmark 51820 table 51820 2>/dev/null");
    system("ip rule del not fwmark 51820 table main 2>/dev/null");   /* legacy */
    system("ip rule del fwmark 51820 table main 2>/dev/null");       /* legacy */
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name);
    system(cmd);
    system("iptables -t nat -F POSTROUTING 2>/dev/null");
    system("iptables -F FORWARD 2>/dev/null");
    printf("TUN %s removed, routes and iptables cleared.\n", name);
    return 0;
}

/* ─── cmd_create_tun ─────────────────────────────────────────────── */

int cmd_create_tun(int is_server)
{
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

    const char *privkey  = iniconf_get(&icfg, "Interface", "PrivateKey");
    const char *pubkey   = iniconf_get(&icfg, "Interface", "PublicKey");
    const char *port     = iniconf_get(&icfg, "Interface", "Port");
    const char *nat_if   = iniconf_get(&icfg, "Tunnel", "NATInterface");
    const char *keepalive = iniconf_get(&icfg, "Tunnel", "Keepalive");

    char pubkey_hex[65] = "";
    {
        const char *home = get_real_home();
        char pub_path[768];
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

    /* [Interface] */
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
                nat_if ? nat_if : detect_default_iface());
        fprintf(out, "# PostDown = iptables -D FORWARD -i %%i -j ACCEPT;"
                     " iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o %s -j MASQUERADE\n",
                nat_if ? nat_if : detect_default_iface());
    } else {
        fprintf(out, "Address = 10.0.0.2/24\n");
    }
    fprintf(out, "\n");

    /* [Peer] sections — iterate all from base config */
    {
        int peer_idx = 0;
        while (1) {
            const char *pk = iniconf_get_indexed(&icfg, "Peer", peer_idx, "PublicKey");
            if (!pk) break;
            const char *ep = iniconf_get_indexed(&icfg, "Peer", peer_idx, "Endpoint");

            fprintf(out, "[Peer]\n");
            fprintf(out, "PublicKey = %s\n", pk);

            if (is_server) {
                fprintf(out, "AllowedIPs = 10.0.0.2/32\n");
                if (ep) fprintf(out, "# Endpoint = %s\n", ep);
            } else {
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
            fprintf(out, "[Peer]\n");
            fprintf(out, "PublicKey = <peer-public-key>\n");
            if (is_server)
                fprintf(out, "AllowedIPs = 10.0.0.2/32\n");
            else {
                fprintf(out, "Endpoint = server.com:9000\n");
                fprintf(out, "AllowedIPs = 0.0.0.0/0\n");
                fprintf(out, "PersistentKeepalive = %s\n", keepalive ? keepalive : "25");
            }
            fprintf(out, "\n");
        }
    }

    /* [Tunnel] */
    fprintf(out, "[Tunnel]\n");
    fprintf(out, "Keepalive = %s\n", keepalive ? keepalive : "30");
    fprintf(out, "NATInterface = %s\n", nat_if ? nat_if : detect_default_iface());
    fprintf(out, "Timeout = 10\n");
    fprintf(out, "MaxConnections = 64\n");

    fclose(out);
    iniconf_free(&icfg);

    printf("TUN %s config written to %s\n", is_server ? "server" : "client", dst);
    printf("\nReview and edit %s if needed, then:\n", dst);
    printf("  sudo ./aegis-tunnel start tun -%s\n", is_server ? "server" : "client");
    return 0;
}
