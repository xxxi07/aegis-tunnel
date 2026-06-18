/*
 * tun.c — TUN virtual network interface implementation
 *
 * Uses Linux TUN/TAP driver via /dev/net/tun.
 * Creates a TUN device (Layer 3, raw IP packets) for VPN operation.
 */
#include "tunnel/tun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

/* ─── Create TUN device ──────────────────────────────────────── */

int tun_create(char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "tun: cannot open /dev/net/tun: %s\n", strerror(errno));
        fprintf(stderr, "     (is the 'tun' kernel module loaded? try: modprobe tun)\n");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* TUN device, no packet info header */
    if (*name) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        fprintf(stderr, "tun: TUNSETIFF failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Copy back the actual interface name */
    strncpy(name, ifr.ifr_name, IFNAMSIZ);
    name[IFNAMSIZ - 1] = '\0';

    /* Set non-blocking for poll() compatibility */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "[tun] created device: %s (fd=%d)\n", name, fd);
    return fd;
}

/* ─── Configure IP address ───────────────────────────────────── */

int tun_set_ip(const char *name, const char *ip, const char *netmask)
{
    char cmd[256];
    /* Parse netmask to CIDR prefix length */
    int prefix = 24; /* default */
    if (netmask) {
        /* Simple conversion: count leading 1 bits in netmask octets */
        unsigned int octets[4];
        if (sscanf(netmask, "%u.%u.%u.%u",
                   &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            prefix = 0;
            for (int i = 0; i < 4; i++) {
                unsigned int o = octets[i];
                while (o) { prefix += (o & 1); o >>= 1; }
            }
        }
    }

    snprintf(cmd, sizeof(cmd),
             "ip addr add %s/%d dev %s 2>/dev/null",
             ip, prefix, name);

    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "tun: failed to set IP on %s (are you root?)\n", name);
        return -1;
    }

    fprintf(stderr, "[tun] %s: %s/%d\n", name, ip, prefix);
    return 0;
}

/* ─── Bring interface up ─────────────────────────────────────── */

int tun_up(const char *name)
{
    char cmd[128];
    int ret;

    /* Bring the interface up */
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", name);
    ret = system(cmd);
    if (ret != 0) {
        /* Fallback: try ifconfig */
        snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", name);
        ret = system(cmd);
    }

    /* Increase txqueuelen from default 500 to 2000.
     * TUN tunnels aggregate all user traffic over a single TCP
     * connection; a burst of ICMP replies, DNS responses, or TCP
     * ACKs can easily exceed 500 packets in a few milliseconds.
     * A larger queue absorbs bursts without kernel drops. */
    snprintf(cmd, sizeof(cmd),
             "ip link set %s txqueuelen 2000 2>/dev/null", name);
    system(cmd);

    return (ret == 0) ? 0 : -1;
}

/* ─── Add route (main table, for server + split-tunnel client) ─── */

#define TUN_ROUTE_TABLE  51820   /* custom table for full-tunnel client */

int tun_add_route(const char *network, const char *name)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip route add %s dev %s 2>/dev/null", network, name);
    int ret = system(cmd);
    if (ret != 0) {
        /* Try replacing if already exists */
        snprintf(cmd, sizeof(cmd),
                 "ip route replace %s dev %s 2>/dev/null", network, name);
        ret = system(cmd);
    }
    return (ret == 0) ? 0 : -1;
}

/* ─── Set SO_MARK on socket ──────────────────────────────────── */

int tun_set_fwmark(int fd, int mark)
{
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        fprintf(stderr, "tun: SO_MARK failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* ─── Full-tunnel routing ────────────────────────────────────── */

int tun_add_full_tunnel(const char *name)
{
    char cmd[256];
    /* Single 0.0.0.0/0 route in the TUN table.
     * Only unmarked packets hit this table (see tun_set_fwmark_rule).
     * The tunnel's own marked TCP packets use the main table → real NIC. */
    snprintf(cmd, sizeof(cmd),
             "ip route add 0.0.0.0/0 dev %s table %d 2>/dev/null",
             name, TUN_ROUTE_TABLE);
    if (system(cmd) != 0) {
        snprintf(cmd, sizeof(cmd),
                 "ip route replace 0.0.0.0/0 dev %s table %d 2>/dev/null",
                 name, TUN_ROUTE_TABLE);
        if (system(cmd) != 0) {
            fprintf(stderr, "tun: failed to add full tunnel route via %s\n", name);
            return -1;
        }
    }
    fprintf(stderr, "[tun] full tunnel: 0.0.0.0/0 → %s (table %d)\n", name, TUN_ROUTE_TABLE);
    return 0;
}

/* ─── fwmark policy routing ──────────────────────────────────── */

int tun_set_fwmark_rule(int mark)
{
    char cmd[256];
    /* Unmarked packets → TUN routing table (has VPN routes).
     * Marked packets (tunnel's own TCP) → default main table → real NIC. */
    snprintf(cmd, sizeof(cmd),
             "ip rule add not fwmark %d table %d 2>/dev/null", mark, TUN_ROUTE_TABLE);
    system(cmd);
    /* Clean up any old broken rule from previous versions */
    snprintf(cmd, sizeof(cmd),
             "ip rule del fwmark %d table main 2>/dev/null", mark);
    system(cmd);
    fprintf(stderr, "[tun] fwmark %d: unmarked→table %d, marked→main\n", mark, TUN_ROUTE_TABLE);
    return 0;
}

/* ─── Enable IP forwarding ───────────────────────────────────── */

int tun_enable_forwarding(void)
{
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) {
        fprintf(stderr, "tun: cannot open /proc/sys/net/ipv4/ip_forward (need root)\n");
        return -1;
    }
    fprintf(fp, "1\n");
    fclose(fp);
    fprintf(stderr, "[tun] IP forwarding: enabled\n");
    return 0;
}

/* ─── Safe command execution (no shell injection) ────────────── */
static int run_iptables(const char *argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Child: exec iptables directly (no shell) */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        execvp("iptables", (char * const *)argv);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ─── iptables NAT (masquerade) ─────────────────────────────── */

int tun_set_nat(const char *subnet, const char *out_if)
{
    const char *check_argv[] = {"iptables","-t","nat","-C","POSTROUTING",
        "-s",subnet,"-o",out_if,"-j","MASQUERADE",NULL};
    if (run_iptables(check_argv) == 0) {
        fprintf(stderr, "[tun] NAT rule already exists\n");
        return 0;
    }

    const char *add_argv[] = {"iptables","-t","nat","-A","POSTROUTING",
        "-s",subnet,"-o",out_if,"-j","MASQUERADE",NULL};
    if (run_iptables(add_argv) != 0) {
        /* Try nftables as fallback */
        char buf[256];
        snprintf(buf,sizeof(buf),"nft add rule ip nat POSTROUTING ip saddr %s oif %s masquerade",subnet,out_if);
        system(buf); /* nft fallback only, low risk */
    }
    fprintf(stderr, "[tun] NAT: %s → %s (MASQUERADE)\n", subnet, out_if);
    return 0;
}

/* ─── iptables FORWARD rules ────────────────────────────────── */

int tun_allow_forward(const char *name)
{
    const char *ci[] = {"iptables","-C","FORWARD","-i",name,"-j","ACCEPT",NULL};
    const char *co[] = {"iptables","-C","FORWARD","-o",name,"-j","ACCEPT",NULL};
    const char *ai[] = {"iptables","-A","FORWARD","-i",name,"-j","ACCEPT",NULL};
    const char *ao[] = {"iptables","-A","FORWARD","-o",name,"-j","ACCEPT",NULL};
    if (run_iptables(ci) != 0) run_iptables(ai);
    if (run_iptables(co) != 0) run_iptables(ao);
    fprintf(stderr, "[tun] FORWARD rules: %s → ACCEPT\n", name);
    return 0;
}

/* ─── DNS firewall rule ─────────────────────────────────────── */

int tun_allow_dns(const char *name, const char *dns_ip)
{
    const char *cc[] = {"iptables","-C","FORWARD","-i",name,
        "-p","udp","--dport","53","-d",dns_ip,"-j","ACCEPT",NULL};
    const char *ca[] = {"iptables","-A","FORWARD","-i",name,
        "-p","udp","--dport","53","-d",dns_ip,"-j","ACCEPT",NULL};
    if (run_iptables(cc) != 0) run_iptables(ca);
    return 0;
}

/* ─── Read IP packet ──────────────────────────────────────────── */

int tun_read(int fd, uint8_t *buf, size_t buflen)
{
    ssize_t n = read(fd, buf, buflen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;  /* no data available (non-blocking) */
        if (errno == EINTR)
            return 0;
        return -1;
    }
    return (int)n;
}

/* ─── Write IP packet ─────────────────────────────────────────── */

int tun_write(int fd, const uint8_t *buf, size_t len)
{
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }
    return (int)n;
}

/* ─── Execute PostUp / PostDown script ────────────────────────── */

int tun_exec_script(const char *script, const char *name)
{
    if (!script || !script[0]) return 0;

    /* Build command with %i substitution */
    char cmd[1024];
    const char *src = script;
    char *dst = cmd;
    size_t remaining = sizeof(cmd) - 1;

    while (*src && remaining > 0) {
        if (src[0] == '%' && src[1] == 'i') {
            size_t nl = strlen(name);
            if (nl > remaining) nl = remaining;
            memcpy(dst, name, nl);
            dst += nl;
            remaining -= nl;
            src += 2;
        } else {
            *dst++ = *src++;
            remaining--;
        }
    }
    *dst = '\0';

    fprintf(stderr, "[tun] exec: %s\n", cmd);

    /* Use fork+exec to avoid system() signal-handling quirks.
     * PostUp/PostDown are shell scripts by design (may contain
     * ; | && etc.), so we invoke /bin/sh -c explicitly. */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[tun] fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Child: preserve stdout/stderr for script diagnostics */
        close(STDIN_FILENO);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[tun] script exited with %d\n", WEXITSTATUS(status));
        return -1;
    }
    return 0;
}

/* ─── Multi-subnet routes ───────────────────────────────────── */

int tun_add_routes_multi(const char *allowed_ips, const char *name)
{
    if (!allowed_ips || !allowed_ips[0]) return 0;

    char buf[256];
    strncpy(buf, allowed_ips, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token, *save = NULL;
    char *ptr = buf;
    while ((token = strtok_r(ptr, ", \t", &save)) != NULL) {
        ptr = NULL;  /* continue parsing same string */
        /* Skip empty tokens */
        while (*token == ' ' || *token == '\t') token++;
        if (!*token) continue;

        /* Full tunnel needs special handling */
        if (!strcmp(token, "0.0.0.0/0") || !strcmp(token, "::/0")) {
            tun_add_full_tunnel(name);
        } else {
            tun_add_route(token, name);
        }
    }
    return 0;
}

/* ─── Multi-subnet NAT ──────────────────────────────────────── */

int tun_set_nat_multi(const char *allowed_ips, const char *out_if)
{
    if (!allowed_ips || !allowed_ips[0]) return 0;

    char buf[256];
    strncpy(buf, allowed_ips, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token, *save = NULL;
    char *ptr = buf;
    while ((token = strtok_r(ptr, ", \t", &save)) != NULL) {
        ptr = NULL;
        while (*token == ' ' || *token == '\t') token++;
        if (!*token) continue;

        /* Don't NAT 0.0.0.0/0 (full tunnel — NAT for all subnets doesn't make sense) */
        if (!strcmp(token, "0.0.0.0/0")) {
            /* NAT for private ranges commonly used behind the server */
            tun_set_nat("10.0.0.0/8", out_if);
            tun_set_nat("172.16.0.0/12", out_if);
            tun_set_nat("192.168.0.0/16", out_if);
        } else {
            tun_set_nat(token, out_if);
        }
    }
    return 0;
}

/* ─── Teardown: clean routes, rules, device on exit ─────────── */

void tun_teardown(const char *name, int is_server)
{
    char cmd[256];

    /* Flush TUN routing table */
    snprintf(cmd, sizeof(cmd), "ip route flush table %d 2>/dev/null", TUN_ROUTE_TABLE);
    system(cmd);

    /* Remove policy routing rules */
    snprintf(cmd, sizeof(cmd),
             "ip rule del not fwmark %d table %d 2>/dev/null",
             TUN_ROUTE_TABLE, TUN_ROUTE_TABLE);
    system(cmd);
    /* Legacy rules from older versions */
    snprintf(cmd, sizeof(cmd),
             "ip rule del not fwmark %d table main 2>/dev/null", TUN_ROUTE_TABLE);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "ip rule del fwmark %d table main 2>/dev/null", TUN_ROUTE_TABLE);
    system(cmd);

    /* Delete TUN device */
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name);
    system(cmd);

    /* Server: clean iptables */
    if (is_server) {
        system("iptables -t nat -F POSTROUTING 2>/dev/null");
        system("iptables -F FORWARD 2>/dev/null");
    }

    fprintf(stderr, "[tun] %s removed, routes and rules cleared.\n", name);
}
