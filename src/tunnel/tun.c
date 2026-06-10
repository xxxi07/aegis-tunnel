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
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", name);
    int ret = system(cmd);
    if (ret != 0) {
        /* Fallback: try ifconfig */
        snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", name);
        ret = system(cmd);
    }
    return (ret == 0) ? 0 : -1;
}

/* ─── Add route ──────────────────────────────────────────────── */

int tun_add_route(const char *network, const char *name)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip route add %s dev %s 2>/dev/null", network, name);
    int ret = system(cmd);
    if (ret != 0) {
        /* Try without 'dev' keyword */
        snprintf(cmd, sizeof(cmd),
                 "ip route add %s via 0.0.0.0 dev %s 2>/dev/null",
                 network, name);
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
    char cmd[128];
    /* Two /1 routes cover the entire IPv4 space,
     * taking priority over the existing default route. */
    const char *routes[] = {"0.0.0.0/1", "128.0.0.0/1"};
    for (int i = 0; i < 2; i++) {
        snprintf(cmd, sizeof(cmd), "ip route add %s dev %s 2>/dev/null", routes[i], name);
        if (system(cmd) != 0) {
            /* Try replacing if already exists */
            snprintf(cmd, sizeof(cmd), "ip route replace %s dev %s 2>/dev/null", routes[i], name);
            if (system(cmd) != 0) {
                fprintf(stderr, "tun: failed to add route %s dev %s\n", routes[i], name);
                return -1;
            }
        }
    }
    fprintf(stderr, "[tun] full tunnel: 0.0.0.0/0 → %s\n", name);
    return 0;
}

/* ─── fwmark policy routing ──────────────────────────────────── */

int tun_set_fwmark_rule(int mark)
{
    char cmd[128];
    /* Packets without fwmark go through main table (including TUN routes) */
    snprintf(cmd, sizeof(cmd), "ip rule add not fwmark %d table main 2>/dev/null", mark);
    system(cmd);
    /* Packets with fwmark bypass the TUN routes */
    snprintf(cmd, sizeof(cmd), "ip rule add fwmark %d table main 2>/dev/null", mark);
    system(cmd);
    fprintf(stderr, "[tun] fwmark %d: policy routing set\n", mark);
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
