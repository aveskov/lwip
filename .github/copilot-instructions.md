# LwIP Wrapper Architecture - Copilot Instructions

This document describes the architecture and design patterns of the `lwip_wrapper` project to help GitHub Copilot and developers understand the codebase.

## Project Overview

This is a **thread-safe wrapper** around the LwIP (Lightweight IP) TCP/IP stack, designed for Windows applications. It provides a simplified C API for creating multiple virtual network connections with independent TCP/UDP operations.

### Key Features
- Multiple virtual network connections with unique source IPs
- Persistent TCP connections for high-performance message sending
- Thread-safe operations with critical sections
- Reference-counted memory management
- Custom source-based routing
- Nagle's algorithm control for latency optimization
- TCP send buffer management with flow control

## Architecture Overview

```
???????????????????????????????????????????????????????????????
?                    Application Layer                         ?
?  (Your C/C++ application using lwip_wrapper API)            ?
???????????????????????????????????????????????????????????????
                    ?
                    ?
???????????????????????????????????????????????????????????????
?                  lwip_wrapper.h/.c                           ?
?  ????????????????????????????????????????????????????????   ?
?  ?  Connection Management (connection_entry_t)          ?   ?
?  ?  - create/close connections                          ?   ?
?  ?  - reference counting                                ?   ?
?  ?  - linked list of connections                        ?   ?
?  ????????????????????????????????????????????????????????   ?
?  ????????????????????????????????????????????????????????   ?
?  ?  TCP Operations                                      ?   ?
?  ?  - Non-persistent (single send + close)             ?   ?
?  ?  - Persistent (reusable connections)                ?   ?
?  ?  - Buffer management & flow control                 ?   ?
?  ????????????????????????????????????????????????????????   ?
?  ????????????????????????????????????????????????????????   ?
?  ?  Thread Safety (CRITICAL_SECTION)                   ?   ?
?  ?  - lwip_lock() / lwip_unlock()                      ?   ?
?  ?  - Atomic reference counting                        ?   ?
?  ????????????????????????????????????????????????????????   ?
?  ????????????????????????????????????????????????????????   ?
?  ?  Custom Routing (ip4_route_custom)                  ?   ?
?  ?  - Source-based routing for multiple interfaces     ?   ?
?  ????????????????????????????????????????????????????????   ?
???????????????????????????????????????????????????????????????
                    ?
                    ?
???????????????????????????????????????????????????????????????
?                   LwIP TCP/IP Stack                          ?
?  - TCP/IP protocol implementation                            ?
?  - Packet buffers (pbuf)                                     ?
?  - Network interfaces (netif)                                ?
?  - Timers and timeouts                                       ?
???????????????????????????????????????????????????????????????
                    ?
                    ?
???????????????????????????????????????????????????????????????
?              Network Layer (Callbacks)                       ?
?  - udp_send_callback_t: Send packets to network             ?
?  - lwip_process_packet: Receive packets from network        ?
???????????????????????????????????????????????????????????????
```

## Core Data Structures

### 1. connection_entry_t
The central structure representing a virtual network connection.

```c
typedef struct connection_entry {
    char* id;                              // Unique connection identifier
    struct netif netif;                    // LwIP network interface
    struct tcp_pcb* pcb;                   // TCP protocol control block
    struct udp_pcb* udp_pcb;              // UDP protocol control block
    ip4_addr_t src_ip;                     // Source IP address for this connection
    char* message;                         // Temporary storage for non-persistent sends
    udp_send_callback_t udp_callback;      // Callback to send packets to network
    send_complete_callback_t send_complete_callback; // Callback when send completes
    struct connection_entry* next;         // Linked list pointer
    volatile int ref_count;                // Reference counter for safe cleanup
    int persistent_mode;                   // Flag: 1 = persistent TCP, 0 = single-send
} connection_entry_t;
```

**Design Pattern**: Reference-counted, linked-list node with embedded LwIP structures.

### 2. Global State
```c
static connection_entry_t* connection_list = NULL;  // Linked list of all connections
static CRITICAL_SECTION lwip_lock_var;             // Thread synchronization
static volatile int lwip_initialized = 0;          // Initialization flag
```

## Key Design Patterns

### 1. Reference Counting Pattern
**Purpose**: Safe memory management in multi-threaded environment

```c
void conn_ref(connection_entry_t* conn) {
    if (conn) {
        InterlockedIncrement(&conn->ref_count);  // Atomic increment
    }
}

void conn_unref(connection_entry_t* conn) {
    if (conn && InterlockedDecrement(&conn->ref_count) == 0) {
        // Cleanup when no references remain
        if (conn->id) free(conn->id);
        if (conn->message) free(conn->message);
        free(conn);
    }
}
```

**Rules**:
- Always `conn_ref()` when storing a connection pointer
- Always `conn_unref()` when done with a connection pointer
- Initial ref_count = 1 (for the connection_list)

### 2. Critical Section Pattern
**Purpose**: Thread-safe access to LwIP and connection list

```c
void lwip_lock(void) {
    if (lwip_initialized) {
        EnterCriticalSection(&lwip_lock_var);
    }
}

void lwip_unlock(void) {
    if (lwip_initialized) {
        LeaveCriticalSection(&lwip_lock_var);
    }
}
```

**Rules**:
- All LwIP API calls must be within lock/unlock
- All connection_list access must be within lock/unlock
- Keep critical sections as short as possible
- Never call callbacks while holding lock

### 3. Callback Pattern
**Purpose**: Decouple network I/O from LwIP stack

```c
// Application implements these:
typedef void (*udp_send_callback_t)(uint8_t* data, int len);
typedef void (*send_complete_callback_t)(void);

// LwIP calls these internally:
static err_t output_cb(struct netif* netif, struct pbuf* p, ...);
static err_t tcp_connected(void* arg, struct tcp_pcb* tpcb, ...);
static err_t on_tcp_sent(void* arg, struct tcp_pcb* tpcb, ...);
static err_t on_tcp_sent_persistent(void* arg, struct tcp_pcb* tpcb, ...);
static void on_tcp_error(void* arg, err_t err);
static err_t tcp_recv_cb(void* arg, struct tcp_pcb* tpcb, ...);
```

### 4. Dual-Mode TCP Pattern
**Purpose**: Support both single-send and persistent connections

```c
// Mode 1: Non-Persistent (one message per connection)
int lwip_tcp_send(const char* id, const char* dest_ip, int port, const char* msg);
// Creates connection -> sends -> closes automatically

// Mode 2: Persistent (reusable connection)
int lwip_tcp_connect_persistent(const char* id, const char* dest_ip, int port);
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len);
void lwip_tcp_disconnect_persistent(const char* id);
// Connect once -> send many times -> disconnect once
```

**Implementation Difference**:
- Non-persistent: `on_tcp_sent()` closes connection after ACK
- Persistent: `on_tcp_sent_persistent()` keeps connection open

## Function Categories

### Initialization & Cleanup
```c
void lwip_init_stack_global(void);           // Initialize LwIP
void init_lwip_lock(void);                   // Initialize critical section
void cleanup_lwip_lock(void);                // Cleanup critical section
void lwip_cleanup_all_connections(void);     // Cleanup all connections
```

### Connection Management
```c
int lwip_create_connection(id, src_ip, netmask, gw, udp_cb, send_cb);
void lwip_close_connection(const char* id);
connection_entry_t* find_connection(const char* id);
```

### TCP Operations
```c
// Non-persistent
int lwip_tcp_send(id, dest_ip, port, message);

// Persistent
int lwip_tcp_connect_persistent(id, dest_ip, port);
int lwip_tcp_send_persistent(id, data, len);  // Returns: 0=ok, -1=error, -2=buffer full
void lwip_tcp_disconnect_persistent(id);
int lwip_tcp_set_nodelay(id, enable);
int lwip_tcp_get_send_buffer_available(id);
```

### UDP Operations
```c
int lwip_udp_send(id, dest_ip, port, data, len);
```

### Packet Processing
```c
void lwip_poll(void);                        // MUST call regularly (every 10-100ms)
void lwip_process_packet(id, data, len);     // Inject received packets into LwIP
```

### Custom Routing
```c
void* ip4_route_custom(const void* src, const void* dest);
```

## Critical Implementation Details

### 1. TCP Send Buffer Management

**Problem**: TCP send buffer can fill up (typically 2-4KB)

**Solution**: Check buffer before sending
```c
u16_t available = tcp_sndbuf(conn->pcb);
if (available < len) {
    return -2;  // Buffer full - retry later
}
```

**Flow Control Pattern**:
```c
int result = lwip_tcp_send_persistent(id, data, len);
if (result == -2) {
    // Buffer full
    lwip_poll();  // Process ACKs to free buffer
    Sleep(50);
    result = lwip_tcp_send_persistent(id, data, len);  // Retry
}
```

### 2. Timer Processing (lwip_poll)

**Critical**: `lwip_poll()` MUST be called regularly

**What it does**:
- Processes TCP retransmissions
- Handles TCP timeouts
- Processes delayed ACKs
- Frees send buffers when ACKs arrive
- Updates ARP cache
- Handles keep-alive

**Frequency**: 10-100ms recommended, never exceed 500ms

**Implementation**:
```c
void lwip_poll() {
    if (!lwip_initialized) return;
    lwip_lock();
    sys_check_timeouts();  // LwIP timer processing
    lwip_unlock();
}
```

### 3. Custom Routing

**Purpose**: Route packets to correct virtual interface based on source IP

**Implementation**:
```c
void* ip4_route_custom(const void* src, const void* dest) {
    const ip4_addr_t* src_ip4 = (const ip4_addr_t*)src;
    
    lwip_lock();
    connection_entry_t* conn = connection_list;
    while (conn) {
        if (ip4_addr_cmp(&conn->src_ip, src_ip4)) {
            struct netif* result = &conn->netif;
            lwip_unlock();
            return result;  // Found matching interface
        }
        conn = conn->next;
    }
    lwip_unlock();
    return NULL;  // No matching interface
}
```

**Hook**: Must be registered in `lwipopts.h`:
```c
#define LWIP_HOOK_IP4_ROUTE(src, dest) ip4_route_custom(src, dest)
```

### 4. Nagle's Algorithm Control

**Default**: Disabled (TCP_NODELAY) for low latency

**Purpose**: 
- Disabled: Send immediately (low latency)
- Enabled: Batch small packets (high throughput)

**Implementation**:
```c
tcp_nagle_disable(conn->pcb);  // Low latency (default)
tcp_nagle_enable(conn->pcb);   // High throughput
```

## Error Handling

### Return Code Convention

| Function Type | Success | Buffer Full | Fatal Error |
|---------------|---------|-------------|-------------|
| `lwip_tcp_send_persistent` | 0 | -2 | -1 |
| Other functions | 0 | N/A | -1 |

### Error Handling Pattern
```c
int result = lwip_tcp_send_persistent(id, data, len);
if (result == 0) {
    // Success - continue
} else if (result == -2) {
    // Buffer full - RETRY after lwip_poll()
    lwip_poll();
    Sleep(50);
    result = lwip_tcp_send_persistent(id, data, len);
} else if (result == -1) {
    // Fatal error - STOP, connection broken
    break;
}
```

## Thread Safety

### Rules
1. **All LwIP calls** must be protected by `lwip_lock()`/`lwip_unlock()`
2. **Reference counting** uses `InterlockedIncrement`/`InterlockedDecrement`
3. **Callbacks** must NOT call back into lwip_wrapper while holding lock
4. **Connection list** access requires lock

### Lock Hierarchy
```
Application Thread
    ??> lwip_lock()
        ??> LwIP API calls
        ??> Connection list access
    ??> lwip_unlock()
    ??> Callbacks (no lock held)
```

## Performance Optimizations

### 1. Persistent Connections
**Speedup**: 2-3x for multiple sends to same destination
- Eliminates TCP handshake overhead (SYN/SYN-ACK/ACK)
- Reuses connection for multiple sends

### 2. Nagle Disabled
**Speedup**: ~33% for small messages
- Sends packets immediately instead of buffering
- Reduces latency by ~200ms per send

### 3. Buffer Pre-checking
**Prevents**: ERR_MEM errors
- Checks `tcp_sndbuf()` before writing
- Returns `-2` for retry instead of failing

## Common Pitfalls & Solutions

### Pitfall 1: Not Calling lwip_poll()
**Symptom**: Connections timeout, buffers never drain
**Solution**: Call `lwip_poll()` every 10-100ms

### Pitfall 2: Retrying on Fatal Error (-1)
**Symptom**: Infinite retry loop on broken connection
**Solution**: Stop immediately on `-1`, only retry on `-2`

### Pitfall 3: Holding Lock During Callback
**Symptom**: Deadlock if callback calls lwip_wrapper
**Solution**: Always unlock before calling user callbacks

### Pitfall 4: Missing conn_unref()
**Symptom**: Memory leak, connections never freed
**Solution**: Always `conn_unref()` when done with connection pointer

### Pitfall 5: Multiple Connections, Same Source IP
**Symptom**: `ip4_route_custom()` returns wrong interface
**Solution**: Use unique source IP for each connection

## Testing Recommendations

### Unit Tests Should Cover
1. Connection creation/cleanup
2. Reference counting correctness
3. Lock acquisition/release
4. Error handling paths
5. Buffer overflow handling

### Integration Tests Should Cover
1. Multiple concurrent connections
2. High-rate message sending
3. Buffer full scenarios with retry
4. Connection timeout/recovery
5. Thread safety under load

### Performance Tests Should Measure
1. Latency: single-send vs persistent
2. Throughput: with/without Nagle
3. Buffer utilization over time
4. CPU usage at different `lwip_poll()` rates

## Code Conventions

### Naming
- **Public API**: `lwip_*` prefix
- **Private functions**: `static`, no prefix or `*_cb` suffix for callbacks
- **Types**: `*_t` suffix
- **Constants**: UPPERCASE

### Memory Management
- **malloc/free**: Wrap with NULL checks
- **strdup**: Use `_strdup` (Windows)
- **Reference counting**: Always use `conn_ref`/`conn_unref`

### Error Handling
- **Return**: 0 = success, negative = error
- **Special**: -2 = retry (buffer full)
- **Cleanup**: Always cleanup on error paths

## Dependencies

### External Libraries
- **LwIP**: TCP/IP stack (see `src/` folder)
- **Windows API**: Critical sections, atomic operations

### Build System
- **CMake**: Version 3.10+
- **Compiler**: C99 standard
- **Generator**: Ninja

## Documentation Files

Located in `docs/` folder:
- `TCP_PERFORMANCE_OPTIMIZATION.md` - Optimization guide
- `FIXING_BUFFER_FULL_ERROR.md` - Buffer management
- `ERROR_HANDLING_GUIDE.md` - Error code handling
- `FIX_BUFFER_AFTER_5_MESSAGES.md` - Specific fix explanation
- `ip4_route_custom_documentation.md` - Routing details
- `working_example_flow_control.c` - Complete example
- `quick_migration_guide.c` - Migration examples

## Quick Reference for Copilot

When suggesting code changes:

1. **Always add `lwip_lock()`/`lwip_unlock()`** around LwIP calls
2. **Always `conn_ref()` before returning** connection pointer
3. **Always `conn_unref()` when done** with connection pointer
4. **Check buffer space** before `tcp_write()` in send functions
5. **Return -2 for buffer full**, -1 for fatal errors
6. **Call `lwip_poll()` regularly** in examples
7. **Use persistent callbacks** for persistent connections
8. **Keep critical sections short** - don't call user code while locked
9. **Handle all error paths** - cleanup on failure
10. **Document callback timing** - when callbacks are invoked

## Version History

- **v1.0**: Initial wrapper with basic TCP/UDP support
- **v2.0**: Added persistent connections and performance optimizations
- **v2.1**: Fixed buffer management, added proper sent callbacks
- **v2.2**: Enhanced error handling, added buffer checking

---

**Last Updated**: 2024
**Maintainer**: See repository contributors
**License**: See LICENSE file in repository root
