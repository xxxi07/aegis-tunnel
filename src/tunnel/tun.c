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

/* ─── iptables NAT (masquerade) ─────────────────────────────── */

int tun_set_nat(const char *subnet, const char *out_if)
{
    /* Check if rule already exists to avoid duplicates */
    char check[256];
    snprintf(check, sizeof(check),
             "iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null",
             subnet, out_if);
    if (system(check) == 0) {
        fprintf(stderr, "[tun] NAT rule already exists for %s → %s\n", subnet, out_if);
        return 0;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null",
             subnet, out_if);
    int ret = system(cmd);
    if (ret != 0) {
        /* Try nftables fallback */
        snprintf(cmd, sizeof(cmd),
                 "nft add rule ip nat POSTROUTING ip saddr %s oif %s masquerade 2>/dev/null",
                 subnet, out_if);
        ret = system(cmd);
    }
    if (ret != 0) {
        fprintf(stderr, "tun: iptables NAT rule failed (need root + iptables)\n");
        return -1;
    }
    fprintf(stderr, "[tun] NAT: %s → %s (MASQUERADE)\n", subnet, out_if);
    return 0;
}

/* ─── iptables FORWARD rules ────────────────────────────────── */

int tun_allow_forward(const char *name)
{
    /* Check if rules already exist */
    char check[256];
    snprintf(check, sizeof(check),
             "iptables -C FORWARD -i %s -j ACCEPT 2>/dev/null", name);
    if (system(check) != 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "iptables -A FORWARD -i %s -j ACCEPT 2>/dev/null", name);
        system(cmd);
    }
    snprintf(check, sizeof(check),
             "iptables -C FORWARD -o %s -j ACCEPT 2>/dev/null", name);
    if (system(check) != 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "iptables -A FORWARD -o %s -j ACCEPT 2>/dev/null", name);
        system(cmd);
    }
    fprintf(stderr, "[tun] FORWARD rules: %s → ACCEPT\n", name);
    return 0;
}

/* ─── DNS firewall rule ─────────────────────────────────────── */

int tun_allow_dns(const char *name, const char *dns_ip)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -i %s -p udp --dport 53 -d %s -j ACCEPT 2>/dev/null",
             name, dns_ip);
    if (system(cmd) != 0) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -A FORWARD -i %s -p udp --dport 53 -d %s -j ACCEPT 2>/dev/null",
                 name, dns_ip);
        system(cmd);
    }
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
