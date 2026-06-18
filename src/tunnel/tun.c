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

/* ─── Forward declarations ───────────────────────────────────── */

static int  run_cmdv(const char *const argv[]);
static void run_cmdv_quiet(const char *const argv[]);

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
    /* Parse netmask to CIDR prefix length */
    int prefix = 24; /* default */
    if (netmask) {
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

    char cidr[32];
    snprintf(cidr, sizeof(cidr), "%s/%d", ip, prefix);

    const char *const argv[] = {"ip", "addr", "add", cidr, "dev", name, NULL};
    if (run_cmdv(argv) != 0) {
        fprintf(stderr, "tun: failed to set IP on %s (are you root?)\n", name);
        return -1;
    }

    fprintf(stderr, "[tun] %s: %s/%d\n", name, ip, prefix);
    return 0;
}

/* ─── Bring interface up ─────────────────────────────────────── */

int tun_up(const char *name)
{
    const char *const ip_up[]  = {"ip", "link", "set", name, "up", NULL};
    int ret = run_cmdv(ip_up);
    if (ret != 0) {
        /* Fallback: try ifconfig */
        const char *const if_up[] = {"ifconfig", name, "up", NULL};
        ret = run_cmdv(if_up);
    }

    /* Increase txqueuelen from default 500 to 2000.
     * TUN tunnels aggregate all user traffic over a single TCP
     * connection; a burst of ICMP replies, DNS responses, or TCP
     * ACKs can easily exceed 500 packets in a few milliseconds.
     * A larger queue absorbs bursts without kernel drops. */
    {
        char qlen[8];
        snprintf(qlen, sizeof(qlen), "%d", 2000);
        const char *const ip_txq[] = {"ip", "link", "set", name,
                                       "txqueuelen", qlen, NULL};
        run_cmdv_quiet(ip_txq);
    }

    return (ret == 0) ? 0 : -1;
}

/* ─── Add route (main table, for server + split-tunnel client) ─── */

#define TUN_ROUTE_TABLE  51820   /* custom table for full-tunnel client */

int tun_add_route(const char *network, const char *name)
{
    const char *const add[] = {"ip", "route", "add", network, "dev", name, NULL};
    int ret = run_cmdv(add);
    if (ret != 0) {
        /* Try replacing if already exists */
        const char *const rep[] = {"ip", "route", "replace", network, "dev", name, NULL};
        ret = run_cmdv(rep);
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
    char table_str[16];
    snprintf(table_str, sizeof(table_str), "%d", TUN_ROUTE_TABLE);

    /* Single 0.0.0.0/0 route in the TUN table.
     * Only unmarked packets hit this table (see tun_set_fwmark_rule).
     * The tunnel's own marked TCP packets use the main table → real NIC. */
    const char *const add[] = {"ip", "route", "add", "0.0.0.0/0",
                                "dev", name, "table", table_str, NULL};
    if (run_cmdv(add) != 0) {
        const char *const rep[] = {"ip", "route", "replace", "0.0.0.0/0",
                                    "dev", name, "table", table_str, NULL};
        if (run_cmdv(rep) != 0) {
            fprintf(stderr, "tun: failed to add full tunnel route via %s\n", name);
            return -1;
        }
    }
    fprintf(stderr, "[tun] full tunnel: 0.0.0.0/0 → %s (table %d)\n",
            name, TUN_ROUTE_TABLE);
    return 0;
}

/* ─── fwmark policy routing ──────────────────────────────────── */

int tun_set_fwmark_rule(int mark)
{
    char mark_str[16], table_str[16];
    snprintf(mark_str,  sizeof(mark_str),  "%d", mark);
    snprintf(table_str, sizeof(table_str), "%d", TUN_ROUTE_TABLE);

    /* Unmarked packets → TUN routing table (has VPN routes).
     * Marked packets (tunnel's own TCP) → default main table → real NIC. */
    {
        const char *const add[] = {"ip", "rule", "add", "not", "fwmark",
                                    mark_str, "table", table_str, NULL};
        run_cmdv_quiet(add);
    }
    /* Clean up any old broken rule from previous versions */
    {
        const char *const del[] = {"ip", "rule", "del", "fwmark",
                                    mark_str, "table", "main", NULL};
        run_cmdv_quiet(del);
    }
    fprintf(stderr, "[tun] fwmark %d: unmarked→table %d, marked→main\n",
            mark, TUN_ROUTE_TABLE);
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

/* ─── Safe command execution (fork+exec, no shell) ───────────── */

/*
 * Execute a command via fork() + execvp().  The argv array MUST be
 * NULL-terminated.  Returns 0 on success (exit code 0), -1 on any
 * error (fork failure, exec failure, non-zero exit).
 *
 * All standard fds are closed in the child so error messages from
 * the subprocess are silenced (equivalent to 2>/dev/null in shell).
 */
static int run_cmdv(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Convenience wrapper that ignores the exit code (fire-and-forget). */
static void run_cmdv_quiet(const char *const argv[])
{
    (void)run_cmdv(argv);
}

/* ─── iptables helper (uses the same fork+exec engine) ─────────── */

static int run_iptables(const char *argv[])
{
    return run_cmdv(argv);
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
        const char *const nft[] = {"nft", "add", "rule", "ip", "nat",
                                    "POSTROUTING", "ip", "saddr", subnet,
                                    "oif", out_if, "masquerade", NULL};
        run_cmdv_quiet(nft);
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
    char table_str[16];
    snprintf(table_str, sizeof(table_str), "%d", TUN_ROUTE_TABLE);

    /* Flush TUN routing table */
    {
        const char *const flush[] = {"ip", "route", "flush", "table", table_str, NULL};
        run_cmdv_quiet(flush);
    }

    /* Remove policy routing rules */
    {
        const char *const del1[] = {"ip", "rule", "del", "not", "fwmark",
                                     table_str, "table", table_str, NULL};
        run_cmdv_quiet(del1);
    }
    /* Legacy rules from older versions */
    {
        const char *const del2[] = {"ip", "rule", "del", "not", "fwmark",
                                     table_str, "table", "main", NULL};
        run_cmdv_quiet(del2);
        const char *const del3[] = {"ip", "rule", "del", "fwmark",
                                     table_str, "table", "main", NULL};
        run_cmdv_quiet(del3);
    }

    /* Delete TUN device */
    {
        const char *const link_del[] = {"ip", "link", "del", name, NULL};
        run_cmdv_quiet(link_del);
    }

    /* Server: clean iptables */
    if (is_server) {
        const char *const nat_flush[] = {"iptables", "-t", "nat", "-F", "POSTROUTING", NULL};
        run_cmdv_quiet(nat_flush);
        const char *const fwd_flush[] = {"iptables", "-F", "FORWARD", NULL};
        run_cmdv_quiet(fwd_flush);
    }

    fprintf(stderr, "[tun] %s removed, routes and rules cleared.\n", name);
}
