#pragma once

void* ip4_route_custom(const void* src_ip, const void* dest_ip);


// OS-less (baremetal)
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0

// Enable basic protocols
#define LWIP_RAW                        1
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_ICMP                       1

#define LWIP_IPV4                       1
#define LWIP_ETHERNET                   1
#define LWIP_ARP                        1

// Memory
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        1600

// Optional: use system-provided struct timeval
#define LWIP_TIMEVAL_PRIVATE            0

// Stats & Debugging
#define LWIP_DEBUG                      0
#define TCP_DEBUG                       LWIP_DBG_OFF
#define PBUF_DEBUG                      LWIP_DBG_OFF
#define MEM_DEBUG                       LWIP_DBG_OFF
#define MEMP_DEBUG                      LWIP_DBG_OFF
#define LWIP_STATS                      0

// No high-level APIs needed
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

// Loopback interface (optional if no real NIC)
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

// IP routing hook for multiple netifs (per-connection routing)
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) ip4_route_custom(src, dest)
