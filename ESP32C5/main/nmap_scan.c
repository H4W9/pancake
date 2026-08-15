#include "nmap_scan.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"

static const char *TAG = "nmap";

/* ── Tunables ──────────────────────────────────────────────────────────── */
#define DISCOVER_MAX_HOSTS             254
#define DISCOVER_ARP_POLL_INTERVAL_MS  200
#define DISCOVER_ARP_POLL_ROUNDS       20
#define DISCOVER_ICMP_WAIT_MS          2000
#define DISCOVER_ICMP_ID               0x4A4E

#define NMAP_PORTS_QUICK    20
#define NMAP_PORTS_MEDIUM   50
#define NMAP_PORTS_HEAVY   100
#define NMAP_CONNECT_TIMEOUT_MS 500

#define NMAP_LINE_LEN   72
#define NMAP_QUEUE_LEN  48

/* ── Output plumbing (task -> UI) ──────────────────────────────────────── */
static QueueHandle_t s_line_q      = NULL;
static volatile bool s_active      = false;
static volatile bool s_stop        = false;
static TaskHandle_t  s_task        = NULL;
static char          s_status[64]  = "";

static void nmap_set_status(const char *s)
{
    strncpy(s_status, s, sizeof(s_status) - 1);
    s_status[sizeof(s_status) - 1] = '\0';
}

/* Push a formatted result/progress line to the UI queue (drops if full). */
static void nmap_emit(const char *fmt, ...)
{
    if (!s_line_q) return;
    char buf[NMAP_LINE_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ESP_LOGI(TAG, "%s", buf);
    xQueueSend(s_line_q, buf, 0);
}

/* ── Port table ────────────────────────────────────────────────────────── */
typedef struct {
    uint16_t port;
    const char *name;
} nmap_port_entry_t;

static const nmap_port_entry_t nmap_ports[] = {
    // --- quick (first 20) ---
    {   21, "FTP"        },
    {   22, "SSH"        },
    {   23, "Telnet"     },
    {   25, "SMTP"       },
    {   53, "DNS"        },
    {   80, "HTTP"       },
    {  110, "POP3"       },
    {  135, "MSRPC"      },
    {  139, "NetBIOS"    },
    {  143, "IMAP"       },
    {  443, "HTTPS"      },
    {  445, "SMB"        },
    {  993, "IMAPS"      },
    { 1433, "MSSQL"      },
    { 3306, "MySQL"      },
    { 3389, "RDP"        },
    { 5432, "PostgreSQL" },
    { 5900, "VNC"        },
    { 8080, "HTTP-alt"   },
    { 8443, "HTTPS-alt"  },
    // --- medium (next 30) ---
    {  111, "RPCbind"    },
    {  161, "SNMP"       },
    {  162, "SNMP-trap"  },
    {  389, "LDAP"       },
    {  465, "SMTPS"      },
    {  514, "Syslog"     },
    {  515, "LPD"        },
    {  554, "RTSP"       },
    {  587, "Submission" },
    {  636, "LDAPS"      },
    {  873, "Rsync"      },
    {  995, "POP3S"      },
    { 1080, "SOCKS"      },
    { 1443, "IES-LM"     },
    { 1521, "Oracle"     },
    { 1883, "MQTT"       },
    { 2049, "NFS"        },
    { 2181, "ZooKeeper"  },
    { 2375, "Docker"     },
    { 3000, "Grafana"    },
    { 3128, "Squid"      },
    { 4443, "Pharos"     },
    { 5000, "UPnP"       },
    { 5060, "SIP"        },
    { 5222, "XMPP"       },
    { 5601, "Kibana"     },
    { 6379, "Redis"      },
    { 8000, "HTTP-alt2"  },
    { 8888, "HTTP-alt3"  },
    { 9090, "Prometheus" },
    // --- heavy (next 50) ---
    {   69, "TFTP"       },
    {  179, "BGP"        },
    {  502, "Modbus"     },
    {  548, "AFP"        },
    {  623, "IPMI"       },
    {  631, "IPP"        },
    {  902, "VMware"     },
    { 1194, "OpenVPN"    },
    { 1234, "VLC"        },
    { 1723, "PPTP"       },
    { 1900, "SSDP"       },
    { 2082, "cPanel"     },
    { 2083, "cPanel-SSL" },
    { 2222, "SSH-alt"    },
    { 2484, "Oracle-SSL" },
    { 3268, "LDAP-GC"    },
    { 3269, "LDAPS-GC"   },
    { 3690, "SVN"        },
    { 4000, "ICQ"        },
    { 4444, "Metasploit" },
    { 4567, "Sinatra"    },
    { 4848, "GlassFish"  },
    { 5353, "mDNS"       },
    { 5433, "PostgreAlt" },
    { 5672, "AMQP"       },
    { 5984, "CouchDB"    },
    { 6000, "X11"        },
    { 6443, "K8s-API"    },
    { 6660, "IRC"        },
    { 6667, "IRC"        },
    { 7001, "WebLogic"   },
    { 7077, "Spark"      },
    { 7474, "Neo4j"      },
    { 8008, "HTTP-alt4"  },
    { 8081, "HTTP-alt5"  },
    { 8181, "HTTP-alt6"  },
    { 8444, "HTTP-alt7"  },
    { 8834, "Nessus"     },
    { 8883, "MQTT-SSL"   },
    { 9000, "SonarQube"  },
    { 9092, "Kafka"      },
    { 9100, "JetDirect"  },
    { 9200, "Elastic"    },
    { 9443, "WSO2"       },
    {10000, "Webmin"     },
    {11211, "Memcached"  },
    {15672, "RabbitMQ"   },
    {25565, "Minecraft"  },
    {27017, "MongoDB"    },
    {28017, "MongoHTTP"  },
    {50000, "SAP"        },
};

/* ── Host discovery ────────────────────────────────────────────────────── */
typedef struct {
    uint32_t ip_addr;      /* network order */
    uint8_t  mac[6];
    bool     mac_known;
} discovered_host_t;

static uint16_t icmp_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len - 1; i += 2)
        sum += (uint16_t)(p[i] << 8 | p[i + 1]);
    if (len & 1)
        sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static bool host_already_found(const discovered_host_t *hosts, int count, uint32_t ip_addr)
{
    for (int i = 0; i < count; i++)
        if (hosts[i].ip_addr == ip_addr) return true;
    return false;
}

/* ARP flood + table polling, then an ICMP ping sweep for anything ARP missed. */
static int discover_lan_hosts(discovered_host_t *hosts, int max_hosts)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        nmap_emit("Not connected — join WiFi first");
        return -1;
    }
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) { nmap_emit("STA interface not found"); return -1; }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        nmap_emit("No IP yet — wait for DHCP");
        return -1;
    }

    uint32_t ip_h   = ntohl(ip_info.ip.addr);
    uint32_t mask_h = ntohl(ip_info.netmask.addr);
    uint32_t network   = ip_h & mask_h;
    uint32_t broadcast = network | ~mask_h;

    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif) { nmap_emit("LwIP netif unavailable"); return -1; }

    int host_count = 0, arp_found = 0;

    /* Phase 1: ARP flood + repeated table polling */
    nmap_set_status("Phase 1: ARP scan...");
    int sent = 0;
    for (uint32_t target = network + 1; target < broadcast && sent < max_hosts; target++, sent++) {
        if (s_stop) return host_count;
        ip4_addr_t tip; tip.addr = htonl(target);
        etharp_request(lwip_netif, &tip);
        if (sent % 10 == 0) vTaskDelay(pdMS_TO_TICKS(10));
    }
    for (int round = 0; round < DISCOVER_ARP_POLL_ROUNDS && !s_stop; round++) {
        vTaskDelay(pdMS_TO_TICKS(DISCOVER_ARP_POLL_INTERVAL_MS));
        for (int i = 0; i < ARP_TABLE_SIZE && host_count < max_hosts; i++) {
            ip4_addr_t *ip_ret; struct netif *nif_ret; struct eth_addr *eth_ret;
            if (etharp_get_entry(i, &ip_ret, &nif_ret, &eth_ret) == 1) {
                if (!host_already_found(hosts, host_count, ip_ret->addr)) {
                    hosts[host_count].ip_addr = ip_ret->addr;
                    memcpy(hosts[host_count].mac, eth_ret->addr, 6);
                    hosts[host_count].mac_known = true;
                    host_count++; arp_found++;
                }
            }
        }
        char st[64]; snprintf(st, sizeof(st), "ARP scan %d/%d (%d found)",
                              round + 1, DISCOVER_ARP_POLL_ROUNDS, arp_found);
        nmap_set_status(st);
    }
    nmap_emit("ARP: %d host(s)", arp_found);
    if (s_stop) return host_count;

    /* Phase 2: ICMP ping sweep for unfound IPs */
    int ping_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ping_sock < 0) return host_count;

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(ping_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    typedef struct __attribute__((packed)) {
        uint8_t type, code; uint16_t checksum, id, seqno;
    } icmp_echo_t;

    nmap_set_status("Phase 2: ICMP ping sweep...");
    int pings_sent = 0; uint16_t seq = 0;
    for (uint32_t target = network + 1; target < broadcast && (int)seq < max_hosts && !s_stop; target++) {
        uint32_t target_net = htonl(target);
        if (host_already_found(hosts, host_count, target_net)) continue;
        icmp_echo_t echo = {0};
        echo.type = 8; echo.code = 0;
        echo.id = htons(DISCOVER_ICMP_ID); echo.seqno = htons(seq++);
        echo.checksum = icmp_checksum(&echo, sizeof(echo));
        struct sockaddr_in dest = { .sin_family = AF_INET, .sin_addr.s_addr = target_net };
        sendto(ping_sock, &echo, sizeof(echo), 0, (struct sockaddr *)&dest, sizeof(dest));
        pings_sent++;
        if (pings_sent % 10 == 0) vTaskDelay(pdMS_TO_TICKS(5));
    }
    vTaskDelay(pdMS_TO_TICKS(DISCOVER_ICMP_WAIT_MS));

    int icmp_found = 0;
    char recv_buf[64];
    struct sockaddr_in from; socklen_t fromlen;
    for (;;) {
        fromlen = sizeof(from);
        int n = recvfrom(ping_sock, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n <= 0) break;
        if (n < 20 + (int)sizeof(icmp_echo_t)) continue;
        int ihl = (recv_buf[0] & 0x0F) * 4;
        if (n < ihl + (int)sizeof(icmp_echo_t)) continue;
        icmp_echo_t *reply = (icmp_echo_t *)(recv_buf + ihl);
        if (reply->type != 0 || reply->code != 0) continue;
        if (ntohs(reply->id) != DISCOVER_ICMP_ID) continue;
        uint32_t src_ip = from.sin_addr.s_addr;
        if (host_count < max_hosts && !host_already_found(hosts, host_count, src_ip)) {
            hosts[host_count].ip_addr = src_ip;
            memset(hosts[host_count].mac, 0, 6);
            hosts[host_count].mac_known = false;
            host_count++; icmp_found++;
        }
    }
    close(ping_sock);
    nmap_emit("ICMP: +%d host(s)", icmp_found);
    return host_count;
}

/* ── TCP port check (non-blocking connect + select timeout) ────────────── */
static bool nmap_check_port(uint32_t ip_net_order, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = ip_net_order,
    };
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) { close(sock); return true; }
    if (errno != EINPROGRESS) { close(sock); return false; }

    fd_set wset; FD_ZERO(&wset); FD_SET(sock, &wset);
    struct timeval tv = {
        .tv_sec  = NMAP_CONNECT_TIMEOUT_MS / 1000,
        .tv_usec = (NMAP_CONNECT_TIMEOUT_MS % 1000) * 1000,
    };
    bool open = false;
    if (select(sock + 1, NULL, &wset, NULL, &tv) > 0) {
        int so_err = 0; socklen_t len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
        open = (so_err == 0);
    }
    close(sock);
    return open;
}

/* ── Scan task ─────────────────────────────────────────────────────────── */
typedef struct { uint32_t single_ip; int port_count; } nmap_args_t;

static void nmap_task(void *arg)
{
    nmap_args_t a = *(nmap_args_t *)arg;
    free(arg);

    discovered_host_t *hosts = calloc(DISCOVER_MAX_HOSTS, sizeof(discovered_host_t));
    if (!hosts) { nmap_emit("Out of memory"); goto done; }

    int host_count = 0;
    if (a.single_ip) {
        hosts[0].ip_addr = a.single_ip;
        hosts[0].mac_known = false;
        host_count = 1;
    } else {
        host_count = discover_lan_hosts(hosts, DISCOVER_MAX_HOSTS);
        if (host_count < 0) { free(hosts); goto done; }
    }
    nmap_emit("Scanning %d host(s), %d ports", host_count, a.port_count);

    int total_open = 0;
    for (int h = 0; h < host_count && !s_stop; h++) {
        uint32_t host_ip = hosts[h].ip_addr;
        ip4_addr_t tmp; tmp.addr = host_ip;
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&tmp));

        nmap_emit("Host: %s", ip_str);
        int open_on_host = 0;
        for (int p = 0; p < a.port_count && !s_stop; p++) {
            if (p % 8 == 0) {
                char st[64];
                snprintf(st, sizeof(st), "%s  port %d/%d", ip_str, p + 1, a.port_count);
                nmap_set_status(st);
            }
            if (nmap_check_port(host_ip, nmap_ports[p].port)) {
                nmap_emit("  %5u/tcp open  %s", nmap_ports[p].port, nmap_ports[p].name);
                open_on_host++; total_open++;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        if (!s_stop && open_on_host == 0) nmap_emit("  (no open ports)");
    }

    if (s_stop) nmap_emit("Stopped by user");
    nmap_emit("Done: %d host(s), %d open port(s)", host_count, total_open);
    free(hosts);

done:
    nmap_set_status(s_stop ? "Stopped" : "Done");
    s_active = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ────────────────────────────────────────────────────────── */
void nmap_scan_init(void)
{
    if (!s_line_q)
        s_line_q = xQueueCreate(NMAP_QUEUE_LEN, NMAP_LINE_LEN);
}

bool nmap_scan_start(uint32_t single_ip, nmap_level_t level)
{
    if (s_active) return false;
    if (!s_line_q) nmap_scan_init();

    xQueueReset(s_line_q);   // drop any stale lines from a previous aborted scan

    nmap_args_t *a = malloc(sizeof(nmap_args_t));
    if (!a) return false;
    a->single_ip  = single_ip;
    a->port_count = (level == NMAP_HEAVY)  ? NMAP_PORTS_HEAVY  :
                    (level == NMAP_MEDIUM) ? NMAP_PORTS_MEDIUM : NMAP_PORTS_QUICK;

    s_stop = false;
    s_active = true;
    nmap_set_status("Starting...");
    if (xTaskCreate(nmap_task, "nmap", 6144, a, 4, &s_task) != pdPASS) {
        s_active = false;
        free(a);
        return false;
    }
    return true;
}

void nmap_scan_stop(void) { s_stop = true; }
bool nmap_scan_is_active(void) { return s_active; }
const char *nmap_scan_status(void) { return s_status; }

bool nmap_scan_poll_line(char *out, size_t outsz)
{
    if (!s_line_q || !out) return false;
    char buf[NMAP_LINE_LEN];
    if (xQueueReceive(s_line_q, buf, 0) != pdTRUE) return false;
    strncpy(out, buf, outsz - 1);
    out[outsz - 1] = '\0';
    return true;
}
