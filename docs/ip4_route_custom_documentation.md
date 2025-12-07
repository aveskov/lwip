# ip4_route_custom Function Documentation

## Purpose
The `ip4_route_custom` function is a **custom routing function** that LwIP uses to find the correct network interface for a given source IP address. It's essential for multi-interface scenarios where multiple virtual connections exist.

## Function Signature
```c
void* ip4_route_custom(const void* src, const void* dest);
```

## Parameters
- `src` - Pointer to source IP address (ip4_addr_t)
- `dest` - Pointer to destination IP address (currently unused in implementation)

## Return Value
- Returns pointer to `struct netif` corresponding to the source IP
- Returns `NULL` if no matching interface is found

## How It Works

```c
void* ip4_route_custom(const void* src, const void* dest) {
    if (!src) {
        return NULL;
    }

    const ip4_addr_t* src_ip4 = (const ip4_addr_t*)src;

    lwip_lock();
    connection_entry_t* conn = connection_list;
    while (conn) {
        // Find connection with matching source IP
        if (ip4_addr_cmp(&conn->src_ip, src_ip4)) {
            struct netif* result = &conn->netif;
            lwip_unlock();            
            return result;
        }
        conn = conn->next;
    }
    lwip_unlock();

    return NULL;
}
```

### Step-by-Step:
1. **Validate input**: Check if source IP is provided
2. **Lock**: Acquire lock for thread-safe access to connection list
3. **Search**: Iterate through all connections
4. **Match**: Find connection where `conn->src_ip` matches the source IP
5. **Return**: Return the network interface (`netif`) for that connection
6. **Unlock**: Release lock

## Why It's Needed

### Problem Without Custom Routing
Without custom routing, LwIP would use its default routing mechanism which:
- Only works with a single network interface
- Can't differentiate between multiple virtual interfaces
- Would route all packets through the same interface

### Solution: Custom Routing
This function enables **source-based routing**:
- Each connection has its own virtual network interface
- Packets are routed based on their **source IP address**
- Multiple virtual connections can coexist independently

## Usage Example

```c
// Create two connections with different source IPs
lwip_create_connection("conn1", "192.168.1.100", "255.255.255.0", "192.168.1.1", 
                      udp_cb, send_cb);
lwip_create_connection("conn2", "10.0.0.100", "255.255.255.0", "10.0.0.1", 
                      udp_cb, send_cb);

// When sending from conn1 (src: 192.168.1.100)
// ip4_route_custom is called internally by LwIP
// It finds conn1's netif and routes packet through it

// When sending from conn2 (src: 10.0.0.100)
// ip4_route_custom finds conn2's netif
// Packet is routed through the correct interface
```

## Integration with LwIP

This function must be registered with LwIP's routing system. Typically done in `lwipopts.h`:

```c
// Custom routing function
#define LWIP_HOOK_IP4_ROUTE(src, dest) ip4_route_custom(src, dest)
```

Or it can be called directly by the SSL/TLS wrapper or other components that need to determine the correct network interface.

## Thread Safety
? **Thread-safe**: Uses `lwip_lock()` and `lwip_unlock()` for synchronization
- Prevents race conditions when accessing connection list
- Safe to call from multiple threads

## Performance Characteristics
- **Time Complexity**: O(n) where n = number of connections
- **Typical Case**: Fast - most applications have few connections
- **Lock Contention**: Minimal - quick lookup operation

## Common Issues and Solutions

### Issue 1: Returns NULL
**Cause**: Source IP doesn't match any connection
**Solution**: Verify connection was created with correct source IP

```c
// Check if connection exists
connection_entry_t* conn = find_connection("conn1");
if (conn) {
    printf("Connection src IP: %s\n", ip4addr_ntoa(&conn->src_ip));
    conn_unref(conn);
}
```

### Issue 2: Wrong Interface Selected
**Cause**: Multiple connections with same source IP
**Solution**: Use unique source IPs for each connection

```c
// WRONG - same source IP
lwip_create_connection("conn1", "192.168.1.100", ...);
lwip_create_connection("conn2", "192.168.1.100", ...); // Conflict!

// CORRECT - unique source IPs
lwip_create_connection("conn1", "192.168.1.100", ...);
lwip_create_connection("conn2", "192.168.1.101", ...);
```

## Relationship with Other Components

### With lwip_wrapper
- Used internally when LwIP needs to route packets
- Works with all connection types (TCP, UDP)
- Transparent to application code

### With SSL/TLS Wrapper
SSL wrappers often need to:
1. Get the source IP: `get_connection_src_ip(conn)`
2. Get the netif: `get_connection_netif(conn)`
3. Or call `ip4_route_custom()` directly for routing

### With lwip_tcp_send
```
lwip_tcp_send()
    ?
tcp_connect() [LwIP internal]
    ?
ip4_route() [LwIP internal]
    ?
LWIP_HOOK_IP4_ROUTE [hook]
    ?
ip4_route_custom() [our implementation]
    ?
Returns correct netif
```

## Best Practices

### 1. Always Use Unique Source IPs
```c
// Good practice
for (int i = 0; i < num_connections; i++) {
    char ip[20];
    sprintf(ip, "192.168.1.%d", 100 + i);
    lwip_create_connection(..., ip, ...);
}
```

### 2. Handle NULL Returns
```c
void* netif = ip4_route_custom(&src_ip, &dest_ip);
if (!netif) {
    printf("ERROR: No route to host\n");
    return -1;
}
```

### 3. Don't Call During Cleanup
```c
// Don't route after closing connection
lwip_close_connection("conn1");
// ip4_route_custom() would return NULL for this connection
```

## Summary

| Aspect | Details |
|--------|---------|
| **Purpose** | Source-based routing for multiple virtual interfaces |
| **Thread Safety** | Yes (uses lwip_lock) |
| **Performance** | O(n) - fast for typical use cases |
| **Required?** | Yes - critical for multi-connection scenarios |
| **Automatic?** | Called internally by LwIP |
| **Customization** | Registered via LWIP_HOOK_IP4_ROUTE |

## Related Functions
- `find_connection()` - Find connection by ID
- `get_connection_netif()` - Get netif from connection
- `get_connection_src_ip()` - Get source IP from connection
- `lwip_create_connection()` - Creates connection with netif

---

**Note**: This function is a core part of the lwip_wrapper infrastructure and should not be removed or modified without understanding the routing implications.
