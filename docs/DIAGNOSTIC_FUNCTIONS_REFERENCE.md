# ACK Queue Diagnostic Functions - Quick Reference

## Overview

Both TCP and SSL persistent connections now have identical diagnostic APIs for monitoring ACK queue health.

---

## TCP Diagnostic Functions

### Get Pending ACK Count
```c
int lwip_tcp_get_pending_ack_count(const char* id);
```
**Returns:** Number of messages waiting for TCP ACK, or -1 on error

**Example:**
```c
int pending = lwip_tcp_get_pending_ack_count("my_tcp_conn");
if (pending > 15) {
    printf("WARNING: High TCP ACK queue: %d messages\n", pending);
}
```

### Get Pending ACK Bytes
```c
int lwip_tcp_get_pending_ack_bytes(const char* id);
```
**Returns:** Total bytes waiting for TCP ACK, or -1 on error

**Example:**
```c
int bytes = lwip_tcp_get_pending_ack_bytes("my_tcp_conn");
printf("TCP ACK queue: %d bytes pending\n", bytes);
```

### Get TCP Send Buffer Available
```c
int lwip_tcp_get_send_buffer_available(const char* id);
```
**Returns:** Available TCP send buffer space in bytes, or -1 on error

**Example:**
```c
int buffer_avail = lwip_tcp_get_send_buffer_available("my_tcp_conn");
if (buffer_avail >= message_size) {
    // Safe to send
    lwip_tcp_send_persistent(id, data, len, msg_id);
} else {
    printf("WARNING: Insufficient buffer (%d < %d)\n", buffer_avail, message_size);
}
```

### Print Detailed State
```c
void lwip_tcp_print_ack_queue_state(const char* id);
```
**Prints:** Complete ACK queue state including:
- Number of pending messages
- Message IDs and byte counts
- TCP send buffer status
- Warning messages if needed

**Example:**
```c
lwip_tcp_print_ack_queue_state("my_tcp_conn");
```

**Output:**
```
=== TCP ACK Queue Status for 'my_tcp_conn' ===
Persistent mode: YES

Pending ACKs:
  [1] msg_id='msg_123' bytes=150
  [2] msg_id='msg_124' bytes=150
  [3] msg_id='msg_125' bytes=150

Total pending: 3 messages, 450 TCP bytes

TCP send buffer: 1850 / 2048 bytes available (90.3% free)
TCP send queue length: 3 segments
======================================
```

---

## SSL Diagnostic Functions

### Get Pending ACK Count
```c
int lwip_ssl_get_pending_ack_count(const char* id);
```
**Returns:** Number of messages waiting for TCP ACK, or -1 on error

**Example:**
```c
int pending = lwip_ssl_get_pending_ack_count("my_ssl_conn");
if (pending > 15) {
    printf("WARNING: High SSL ACK queue: %d messages\n", pending);
}
```

### Get Pending ACK Bytes
```c
int lwip_ssl_get_pending_ack_bytes(const char* id);
```
**Returns:** Total bytes waiting for TCP ACK (includes SSL overhead), or -1 on error

**Example:**
```c
int bytes = lwip_ssl_get_pending_ack_bytes("my_ssl_conn");
printf("SSL ACK queue: %d bytes pending (with SSL overhead)\n", bytes);
```

### Get TCP Send Buffer Available
```c
int lwip_ssl_get_send_buffer_available(const char* id);
```
**Returns:** Available TCP send buffer space in bytes, or -1 on error

**Example:**
```c
int buffer_avail = lwip_ssl_get_send_buffer_available("my_ssl_conn");
if (buffer_avail >= message_size) {
    // Safe to send
    lwip_ssl_send_persistent(id, data, len, msg_id);
} else {
    printf("WARNING: Insufficient buffer (%d < %d)\n", buffer_avail, message_size);
}
```

### Print Detailed State
```c
void lwip_ssl_print_ack_queue_state(const char* id);
```
**Prints:** Complete ACK queue state including:
- Connection state and mode
- Number of pending messages
- Message IDs and byte counts
- TCP send buffer status
- Warning messages if needed

**Example:**
```c
lwip_ssl_print_ack_queue_state("my_ssl_conn");
```

**Output:**
```
=== SSL ACK Queue Status for 'my_ssl_conn' ===
Connection state: 2 (0=CONNECTING, 2=CONNECTED)
Connection mode: 1 (0=SINGLE_SEND, 1=PERSISTENT)
Total messages sent: 250

Pending ACKs:
  [1] msg_id='msg_123' bytes=180
  [2] msg_id='msg_124' bytes=180
  [3] msg_id='msg_125' bytes=180

Total pending: 3 messages, 540 TCP bytes

TCP send buffer: 1820 / 2048 bytes available (88.9% free)
TCP send queue length: 3 segments
======================================
```

---

## Usage Patterns

### Pattern 1: Simple Health Check
```c
void check_health(const char* tcp_id, const char* ssl_id) {
    int tcp_pending = lwip_tcp_get_pending_ack_count(tcp_id);
    int ssl_pending = lwip_ssl_get_pending_ack_count(ssl_id);
    
    printf("TCP: %d pending, SSL: %d pending\n", tcp_pending, ssl_pending);
}
```

### Pattern 2: Monitor Before Send
```c
int safe_send(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Check queue before sending
    int pending = lwip_tcp_get_pending_ack_count(id);
    
    if (pending > 20) {
        printf("Queue full, waiting...\n");
        
        // Wait for drain
        while (pending > 15) {
            Sleep(50);
            pending = lwip_tcp_get_pending_ack_count(id);
        }
    }
    
    return lwip_tcp_send_persistent(id, data, len, msg_id);
}
```

### Pattern 3: Continuous Monitoring Thread
```c
DWORD WINAPI monitor_thread(LPVOID param) {
    const char* conn_id = (const char*)param;
    
    while (running) {
        int pending = lwip_tcp_get_pending_ack_count(conn_id);
        
        if (pending > 20) {
            printf("ALERT: High ACK queue: %d\n", pending);
            lwip_tcp_print_ack_queue_state(conn_id);
        }
        
        Sleep(1000);
    }
    return 0;
}
```

### Pattern 4: Adaptive Rate Limiting
```c
void send_with_adaptive_rate(const char* id, /* ... */) {
    int pending = lwip_tcp_get_pending_ack_count(id);
    
    // Adjust delay based on queue size
    int delay_ms;
    if (pending < 5) {
        delay_ms = 0;      // Fast lane
    } else if (pending < 10) {
        delay_ms = 10;     // Normal
    } else if (pending < 15) {
        delay_ms = 50;     // Slow down
    } else {
        delay_ms = 100;    // Critical - slow way down
    }
    
    Sleep(delay_ms);
    lwip_tcp_send_persistent(id, data, len, msg_id);
}
```

### Pattern 5: Debug on Error
```c
int result = lwip_tcp_send_persistent(id, data, len, msg_id);

if (result != 0) {
    printf("Send failed with code: %d\n", result);
    
    // Print detailed state for debugging
    lwip_tcp_print_ack_queue_state(id);
    
    // Get specific metrics
    int pending = lwip_tcp_get_pending_ack_count(id);
    int bytes = lwip_tcp_get_pending_ack_bytes(id);
    int buffer_avail = lwip_tcp_get_send_buffer_available(id);
    
    printf("Queue: %d messages, %d bytes\n", pending, bytes);
    printf("TCP buffer: %d bytes available\n", buffer_avail);
}
```

---

## Comparison: TCP vs SSL

| Feature | TCP Function | SSL Function |
|---------|-------------|--------------|
| Get pending count | `lwip_tcp_get_pending_ack_count()` | `lwip_ssl_get_pending_ack_count()` |
| Get pending bytes | `lwip_tcp_get_pending_ack_bytes()` | `lwip_ssl_get_pending_ack_bytes()` |
| Get buffer available | `lwip_tcp_get_send_buffer_available()` | `lwip_ssl_get_send_buffer_available()` |
| Print state | `lwip_tcp_print_ack_queue_state()` | `lwip_ssl_print_ack_queue_state()` |
| **Byte count includes** | Raw TCP data | TCP + SSL overhead (~30 bytes/msg) |

---

## When to Use Each Function

### Use `get_pending_ack_count()` when:
- ? Checking if it's safe to send more messages
- ? Implementing rate limiting
- ? Simple health monitoring
- ? Quick queue size check

### Use `get_pending_ack_bytes()` when:
- ? Monitoring network bandwidth usage
- ? Comparing TCP buffer usage
- ? Detecting large message backlog
- ? Calculating network load

### Use `print_ack_queue_state()` when:
- ? Debugging ACK queue issues
- ? Understanding queue contents
- ? Analyzing send patterns
- ? Troubleshooting performance problems

---

## Return Values

All `get_*` functions return:
- **>= 0**: Success (count or bytes)
- **-1**: Error (connection not found, not persistent, or not initialized)

The `print_*` functions return void and print directly to stdout.

---

## Best Practices

1. **Check before sending:**
   ```c
   if (lwip_tcp_get_pending_ack_count(id) < 15) {
       lwip_tcp_send_persistent(id, data, len, msg_id);
   }
   ```

2. **Monitor regularly:**
   ```c
   // Every 1-2 seconds
   int pending = lwip_tcp_get_pending_ack_count(id);
   if (pending > 20) log_warning("High ACK queue");
   ```

3. **Debug with details:**
   ```c
   if (error_occurred) {
       lwip_tcp_print_ack_queue_state(id);
   }
   ```

4. **Use bytes for bandwidth:**
   ```c
   int bytes = lwip_tcp_get_pending_ack_bytes(id);
   float kb_pending = bytes / 1024.0;
   printf("%.1f KB pending\n", kb_pending);
   ```

---

## Warning Thresholds

| Metric | Good | Warning | Critical |
|--------|------|---------|----------|
| Pending count | 0-10 | 10-20 | >20 |
| Pending bytes | 0-1KB | 1-2KB | >2KB |
| TCP buffer free | >50% | 25-50% | <25% |

---

## Integration with Existing Code

Both TCP and SSL use the **same diagnostic API pattern**, making it easy to:

- Write generic monitoring functions
- Share health check code
- Compare connection types
- Build unified dashboards

**Example:**
```c
typedef enum { CONN_TYPE_TCP, CONN_TYPE_SSL } conn_type_t;

int get_pending_count(const char* id, conn_type_t type) {
    return (type == CONN_TYPE_TCP) 
        ? lwip_tcp_get_pending_ack_count(id)
        : lwip_ssl_get_pending_ack_count(id);
}
```

---

## Quick Troubleshooting

**Problem:** Function returns -1

**Possible causes:**
1. Connection ID doesn't exist
2. Connection is not persistent
3. Connection not initialized yet

**Solution:**
```c
int pending = lwip_tcp_get_pending_ack_count(id);
if (pending < 0) {
    printf("ERROR: Invalid connection or not persistent\n");
    // Check connection exists and is persistent mode
}
```

---

## Summary

? **Identical APIs** for TCP and SSL  
? **Three functions** per connection type  
? **Easy integration** with existing code  
? **Thread-safe** (uses internal locking)  
? **No performance impact** (quick linked list traversal)  

Use these functions to **monitor**, **debug**, and **optimize** your persistent TCP and SSL connections!
