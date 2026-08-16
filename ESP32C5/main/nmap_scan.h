/*
 * nmap_scan — lightweight LAN host discovery + TCP port scanner.
 * Ported from projectZero (C5Lab). Pure lwIP sockets + ARP/ICMP; no extra HW.
 * Requires an active WiFi STA connection with a DHCP-assigned IP.
 *
 * The scan runs on its own FreeRTOS task. Result/progress lines are pushed to an
 * internal queue that the UI drains from the LVGL thread via nmap_scan_poll_line();
 * a single live status line is available via nmap_scan_status().
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    NMAP_QUICK  = 0,   /* first 20 ports  */
    NMAP_MEDIUM = 1,   /* first 50 ports  */
    NMAP_HEAVY  = 2,   /* all 100 ports   */
} nmap_level_t;

/* Create the internal output queue. Call once at boot. */
void nmap_scan_init(void);

/* Start a scan on a background task.
 *   single_ip : network-order IPv4 (e.g. from inet_addr) to scan one host, or
 *               0 to discover + sweep the whole local /24-ish subnet.
 *   level     : how many ports per host.
 * Returns false if a scan is already running or the task can't be created. */
bool nmap_scan_start(uint32_t single_ip, nmap_level_t level);

/* Request the running scan to stop (asynchronous). */
void nmap_scan_stop(void);

/* True while the scan task is running. */
bool nmap_scan_is_active(void);

/* Drain one output line from the UI thread. Returns true (and fills out) if a
 * line was available, false if the queue is empty. */
bool nmap_scan_poll_line(char *out, size_t outsz);

/* Current one-line live status (progress). Always NUL-terminated. */
const char *nmap_scan_status(void);
