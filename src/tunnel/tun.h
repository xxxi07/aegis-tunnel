/*
 * tun.h — TUN virtual network interface (Layer 3 VPN)
 *
 * Creates a TUN device that exchanges raw IP packets between
 * the kernel network stack and userspace.  Combined with the
 * AEGIS-Tunnel encryption layer, this provides a full VPN.
 *
 * Usage:
 *   int tun_fd = tun_create("tun0");
 *   tun_set_ip("tun0", "10.0.0.1", "255.255.255.0");
 *   // Read IP packets from tun_fd, encrypt, send to peer
 *   // Receive encrypted packets from peer, decrypt, write to tun_fd
 *
 * Wire format for VPN mode (sent through AEGIS-Tunnel frames):
 *   [IP packet (20-65535 bytes)]
 *
 * Requires: Linux kernel TUN driver (/dev/net/tun), CAP_NET_ADMIN
 */
#ifndef TUN_H
#define TUN_H

#include <stddef.h>
#include <stdint.h>

#define TUN_MAX_PACKET  65535   /* max IP packet size (including jumbo) */
#define TUN_DEFAULT_MTU  1500   /* typical Ethernet MTU */

/*
 * Create a TUN device.
 *   name: desired interface name (e.g., "tun0").  May be modified
 *         by the kernel to the actual name if the requested one
 *         is already in use.  Buffer must be at least IFNAMSIZ (16).
 * Returns fd on success, -1 on error.
 */
int tun_create(char *name);

/*
 * Set IP address and netmask on a TUN interface.
 * Uses `ip addr add` command (simplest portable approach).
 *   name:    interface name (e.g., "tun0")
 *   ip:      IPv4 address (e.g., "10.0.0.1")
 *   netmask: subnet mask (e.g., "255.255.255.0")
 * Returns 0 on success, -1 on error.
 */
int tun_set_ip(const char *name, const char *ip, const char *netmask);

/*
 * Bring the interface up.
 *   name: interface name
 * Returns 0 on success, -1 on error.
 */
int tun_up(const char *name);

/*
 * Add a route through the TUN interface.
 *   network: destination network (e.g., "10.0.0.0/24")
 *   name:    TUN interface name
 * Returns 0 on success, -1 on error.
 */
int tun_add_route(const char *network, const char *name);

/*
 * Set SO_MARK on a socket to bypass TUN routing (prevents loop).
 * WireGuard-style: encrypted tunnel traffic must not be routed
 * back into the TUN device.
 *
 *   mark: fwmark value (e.g., 51820 like WireGuard default)
 */
int tun_set_fwmark(int fd, int mark);

/*
 * Set up full-tunnel routing (redirect all traffic through TUN).
 *
 * When allowed_ips is "0.0.0.0/0" or "::/0", adds split-default routes:
 *   ip route add 0.0.0.0/1 dev <name>
 *   ip route add 128.0.0.0/1 dev <name>
 *
 * This overrides the default route without deleting it.
 * Must be paired with tun_set_fwmark on the tunnel socket
 * to prevent the encrypted traffic itself from looping.
 *
 * Returns 0 on success, -1 on error.
 */
int tun_add_full_tunnel(const char *name);

/*
 * Set up policy routing to exclude fwmark'd packets from TUN routes.
 *   ip rule add not fwmark <mark> table main
 *
 * Ensures the tunnel's own TCP connection goes through the real NIC,
 * not through the TUN device (which would cause a loop).
 */
int tun_set_fwmark_rule(int mark);

/*
 * Enable IP forwarding (required for VPN gateway).
 *   echo 1 > /proc/sys/net/ipv4/ip_forward
 * Returns 0 on success, -1 on error.
 */
int tun_enable_forwarding(void);

/*
 * Add iptables NAT (masquerade) rule.
 *   iptables -t nat -A POSTROUTING -s <subnet> -o <out_if> -j MASQUERADE
 * Allows TUN clients to access the internet through this server.
 *   subnet: TUN network (e.g., "10.0.0.0/24")
 *   out_if: external interface (e.g., "eth0")
 * Returns 0 on success, -1 on error.
 */
int tun_set_nat(const char *subnet, const char *out_if);

/*
 * Add iptables FORWARD rules for TUN interface.
 *   iptables -A FORWARD -i <name> -j ACCEPT
 *   iptables -A FORWARD -o <name> -j ACCEPT
 * Returns 0 on success, -1 on error.
 */
int tun_allow_forward(const char *name);

/*
 * Setup firewall rules for DNS (optional, for split-tunnel).
 * Allows DNS queries through the tunnel only.
 * Returns 0 on success, -1 on error.
 */
int tun_allow_dns(const char *name, const char *dns_ip);

/*
 * Execute a shell script, substituting %i with the interface name.
 * Used for PostUp / PostDown hooks (WireGuard-style).
 *   script: shell command line (may contain %i)
 *   name:   TUN interface name
 * Returns 0 on success, -1 on error.
 */
int tun_exec_script(const char *script, const char *name);

/*
 * Tear down TUN device: flush custom routing table, remove policy rules,
 * delete the interface, and optionally clean iptables (server mode).
 * Called automatically on exit — no need for manual 'tun down'.
 */
void tun_teardown(const char *name, int is_server);

/*
 * Parse comma-separated AllowedIPs and add routes for each subnet.
 *   allowed_ips: comma-separated CIDR list (e.g., "10.0.0.0/24,192.168.1.0/24")
 *   name:       TUN interface name
 * Returns 0 on success.
 */
int tun_add_routes_multi(const char *allowed_ips, const char *name);

/*
 * Parse comma-separated AllowedIPs and add NAT for each subnet.
 *   allowed_ips: comma-separated CIDR list
 *   out_if:      external interface for MASQUERADE
 * Returns 0 on success.
 */
int tun_set_nat_multi(const char *allowed_ips, const char *out_if);

/*
 * Read an IP packet from the TUN device.
 * Blocks until a packet is available.
 * Returns packet length on success, -1 on error.
 * On success, buf contains one complete IP packet.
 */
int tun_read(int fd, uint8_t *buf, size_t buflen);

/*
 * Write an IP packet to the TUN device.
 * Returns bytes written on success, -1 on error.
 */
int tun_write(int fd, const uint8_t *buf, size_t len);

#endif /* TUN_H */
