/*
 * config_mgmt.h — Configuration management (subcommands)
 *
 * Handles keygen, peer management, TUN config generation,
 * and status display.  Separated from main.c for readability.
 */
#ifndef CONFIG_MGMT_H
#define CONFIG_MGMT_H

/* ── System helpers (also used by main.c) ── */
const char *get_real_home(void);
const char *detect_default_iface(void);

/* ── Subcommands ── */
int cmd_keygen(void);
int cmd_peer_add(const char *host, const char *hex_or_file);
int cmd_peer_delete(const char *name);
int cmd_peer_list(void);
int cmd_status(void);
int cmd_tun_down(const char *name);
int cmd_create_tun(int is_server);

#endif /* CONFIG_MGMT_H */
