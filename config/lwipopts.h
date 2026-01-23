#pragma once

void* ip4_route_custom(const void* src_ip, const void* dest_ip);

#ifdef LWIP_WRAPPER_ENABLE_PRINT
    #define LWIP_PRINTF printf
#else
    #define LWIP_PRINTF(...) ((void)0)
#endif

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

// ===== HIGH-PERFORMANCE MEMORY CONFIGURATION =====
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        (128 * 1024)    // 128KB heap (was 16KB) - for high message rate

// ===== HIGH-THROUGHPUT TCP CONFIGURATION (Optimized for 300-byte messages) =====
#define TCP_MSS                         1460             // Standard Ethernet MSS

// CRITICAL: Large buffers for pipelining multiple 300-byte messages
#define TCP_SND_BUF                     (32 * 1024)      // 32KB send buffer (was 11KB) - holds ~100 messages
#define TCP_SND_QUEUELEN                (6 * (TCP_SND_BUF) / (TCP_MSS))  // Enough queue entries
#define TCP_WND                         (64 * 1024)      // 64KB receive window (was 5KB) - high throughput

// Enable Window Scaling for >64KB windows (CRITICAL for throughput)
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   3                // Window scale factor: 64KB * 2^3 = 512KB max

// Memory pools optimized for high message rate
#define MEMP_NUM_TCP_SEG                128              // More TCP segments (was 16) - for 300-byte bursts
#define PBUF_POOL_SIZE                  256              // More packet buffers (was 16)
#define PBUF_POOL_BUFSIZE               1536             // Larger buffer size for efficiency

// TCP Performance Optimizations
#define TCP_QUEUE_OOSEQ                 1                // Handle out-of-order segments
#define TCP_OVERSIZE                    TCP_MSS          // Preallocate for coalescing
#define LWIP_TCP_TIMESTAMPS             1                // Better RTT estimation

// ===== TCP KEEP-ALIVE CONFIGURATION =====
// Enable TCP keep-alive to prevent persistent connections from timing out
#define LWIP_TCP_KEEPALIVE              1                // Enable keep-alive support
#define TCP_KEEPIDLE_DEFAULT            7200000          // 2 hours in milliseconds (default)
#define TCP_KEEPINTVL_DEFAULT           75000            // 75 seconds between probes
#define TCP_KEEPCNT_DEFAULT             9                // 9 probes before giving up

// Optional: use system-provided struct timeval
#define LWIP_TIMEVAL_PRIVATE            0

// Stats & Debugging - DISABLED for performance
#define LWIP_DEBUG                      0
#define LWIP_DBG_TYPES_ON               LWIP_DBG_OFF
#define TCP_DEBUG                       LWIP_DBG_OFF
#define PBUF_DEBUG                      LWIP_DBG_OFF 
#define MEM_DEBUG                       LWIP_DBG_OFF
#define MEMP_DEBUG                      LWIP_DBG_OFF
#define LWIP_STATS                      0
#define MEM_STATS                       0
#define MEMP_STATS                      0
#define TCP_STATS                       0

// No high-level APIs needed
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

// Loopback interface (optional if no real NIC)
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

// IP routing hook for multiple netifs (per-connection routing)
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) ip4_route_custom(src, dest)
