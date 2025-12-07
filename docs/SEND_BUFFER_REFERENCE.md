# Send Buffer Availability - Quick Reference

## Function Signatures

### TCP
```c
int lwip_tcp_get_send_buffer_available(const char* id);
```

### SSL
```c
int lwip_ssl_get_send_buffer_available(const char* id);
```

## Return Values

| Value | Meaning |
|-------|---------|
| `>= 0` | Number of bytes available in TCP send buffer |
| `-1` | Error: Connection not found, not connected, or not persistent |

## Typical Buffer Size

Default: **2048 bytes** (TCP_SND_BUF in lwipopts.h)

## Quick Examples

### Example 1: Check Before Send
```c
int buffer_avail = lwip_ssl_get_send_buffer_available("ssl_conn");

if (buffer_avail >= message_length) {
    // Safe to send
    lwip_ssl_send_persistent(id, data, len, msg_id);
} else {
    // Wait for buffer
    printf("Buffer too full: %d < %d\n", buffer_avail, message_length);
}
```

### Example 2: Wait for Buffer Space
```c
int buffer_avail = lwip_ssl_get_send_buffer_available("ssl_conn");

while (buffer_avail < message_length) {
    printf("Waiting for buffer space...\n");
    Sleep(50);
    lwip_poll();
    buffer_avail = lwip_ssl_get_send_buffer_available("ssl_conn");
}

// Now send
lwip_ssl_send_persistent(id, data, len, msg_id);
```

### Example 3: Monitor Buffer Usage
```c
int buffer_avail = lwip_ssl_get_send_buffer_available("ssl_conn");
int buffer_max = 2048;  // Or your configured TCP_SND_BUF size

float usage_pct = ((buffer_max - buffer_avail) * 100.0) / buffer_max;

printf("Buffer: %d/%d bytes available (%.1f%% used)\n", 
       buffer_avail, buffer_max, usage_pct);

if (usage_pct > 75.0) {
    printf("WARNING: High buffer usage!\n");
}
```

### Example 4: Adaptive Rate Limiting
```c
int buffer_avail = lwip_ssl_get_send_buffer_available("ssl_conn");

// Adjust send rate based on buffer availability
if (buffer_avail > 1536) {
    // >75% free - full speed, no delay
    delay_ms = 0;
} else if (buffer_avail > 1024) {
    // 50-75% free - normal speed
    delay_ms = 10;
} else if (buffer_avail > 512) {
    // 25-50% free - slow down
    delay_ms = 50;
} else {
    // <25% free - very slow
    delay_ms = 100;
}

Sleep(delay_ms);
lwip_ssl_send_persistent(id, data, len, msg_id);
```

## Use Cases

### ? When to Use

1. **Before sending large messages**
   ```c
   if (lwip_ssl_get_send_buffer_available(id) >= large_message_size) {
       lwip_ssl_send_persistent(...);
   }
   ```

2. **During high-rate sending**
   ```c
   for (int i = 0; i < 1000; i++) {
       // Check buffer every iteration
       int avail = lwip_ssl_get_send_buffer_available(id);
       if (avail < MIN_BUFFER_SPACE) {
           lwip_poll();
           Sleep(10);
       }
       lwip_ssl_send_persistent(...);
   }
   ```

3. **Implementing flow control**
   ```c
   while (has_data_to_send()) {
       int buffer = lwip_ssl_get_send_buffer_available(id);
       if (buffer >= next_message_size()) {
           send_next_message();
       } else {
           wait_for_buffer();
       }
   }
   ```

4. **Monitoring connection health**
   ```c
   if (lwip_ssl_get_send_buffer_available(id) == 0) {
       printf("WARNING: Send buffer completely full!\n");
       check_network_issues();
   }
   ```

## Warning Thresholds

| Buffer Available | Status | Action |
|------------------|--------|--------|
| > 1536 bytes | Good (>75% free) | Full speed sending |
| 1024-1536 bytes | OK (50-75% free) | Normal operation |
| 512-1024 bytes | Warning (25-50% free) | Slow down sending |
| < 512 bytes | Critical (<25% free) | Wait for buffer to drain |
| 0 bytes | Full | Must wait, cannot send |

## Common Patterns

### Pattern 1: Safe Send Function
```c
int safe_send(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Check buffer
    int buffer_avail = lwip_ssl_get_send_buffer_available(id);
    
    if (buffer_avail < len) {
        // Wait for space
        int wait_count = 0;
        while (buffer_avail < len && wait_count < 100) {
            Sleep(20);
            lwip_poll();
            buffer_avail = lwip_ssl_get_send_buffer_available(id);
            wait_count++;
        }
        
        if (buffer_avail < len) {
            return -3;  // Timeout
        }
    }
    
    // Send
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

### Pattern 2: Batch Send with Buffer Monitoring
```c
int batch_send(const char* id, message_t* messages, int count) {
    int sent = 0;
    
    for (int i = 0; i < count; i++) {
        // Check buffer before each send
        int buffer = lwip_ssl_get_send_buffer_available(id);
        
        if (buffer < messages[i].length) {
            // Buffer full - process pending data
            lwip_poll();
            Sleep(50);
            i--;  // Retry this message
            continue;
        }
        
        // Send
        int result = lwip_ssl_send_persistent(id, 
                                               messages[i].data, 
                                               messages[i].length, 
                                               messages[i].id);
        if (result == 0) {
            sent++;
        }
    }
    
    return sent;
}
```

### Pattern 3: Buffer Monitor Thread
```c
DWORD WINAPI monitor_thread(LPVOID param) {
    const char* conn_id = (const char*)param;
    
    while (running) {
        int buffer = lwip_ssl_get_send_buffer_available(conn_id);
        
        if (buffer >= 0) {
            float usage = ((2048 - buffer) * 100.0) / 2048;
            
            if (usage > 90.0) {
                printf("CRITICAL: Buffer %d%% full\n", (int)usage);
            }
        }
        
        Sleep(500);
    }
    return 0;
}
```

## Integration with Other Diagnostics

### Combined Health Check
```c
void check_connection_health(const char* id) {
    // Get all metrics
    int buffer_avail = lwip_ssl_get_send_buffer_available(id);
    int pending_acks = lwip_ssl_get_pending_ack_count(id);
    int pending_bytes = lwip_ssl_get_pending_ack_bytes(id);
    int is_connected = lwip_ssl_is_connected(id);
    
    printf("=== Connection Health ===\n");
    printf("Connected: %s\n", is_connected ? "YES" : "NO");
    printf("Buffer available: %d bytes\n", buffer_avail);
    printf("Pending ACKs: %d messages (%d bytes)\n", pending_acks, pending_bytes);
    
    // Calculate health score
    int health_score = 100;
    
    if (buffer_avail < 512) health_score -= 30;
    if (pending_acks > 20) health_score -= 30;
    if (!is_connected) health_score = 0;
    
    printf("Health score: %d/100\n", health_score);
}
```

## Troubleshooting

### Problem: Function returns -1

**Possible causes:**
1. Connection ID doesn't exist
2. Connection not established yet
3. Connection is not persistent mode
4. Connection has been closed

**Solution:**
```c
int buffer = lwip_ssl_get_send_buffer_available(id);
if (buffer < 0) {
    // Check connection status first
    if (!lwip_ssl_is_connected(id)) {
        printf("ERROR: SSL connection not established\n");
    } else {
        printf("ERROR: Invalid connection or not persistent\n");
    }
}
```

### Problem: Buffer always shows 0

**Possible causes:**
1. Sending too fast without calling `lwip_poll()`
2. Network congestion or slow receiver
3. TCP ACKs not being received

**Solution:**
```c
// Make sure to call lwip_poll() regularly
while (running) {
    lwip_poll();  // Process TCP ACKs
    Sleep(50);
}

// Check if ACKs are arriving
int pending = lwip_ssl_get_pending_ack_count(id);
printf("Pending ACKs: %d (should decrease over time)\n", pending);
```

## Best Practices

1. ? **Check buffer before large sends**
2. ? **Monitor buffer during high-rate sending**
3. ? **Implement adaptive rate limiting**
4. ? **Wait/retry if buffer is full**
5. ? **Call `lwip_poll()` regularly to drain buffer**
6. ? **Use with ACK queue diagnostics for complete picture**

## Summary

| Metric | Function | Good Value | Warning Value |
|--------|----------|------------|---------------|
| Buffer available | `lwip_ssl_get_send_buffer_available()` | >1024 bytes | <512 bytes |
| Pending ACKs | `lwip_ssl_get_pending_ack_count()` | <10 messages | >20 messages |
| Pending bytes | `lwip_ssl_get_pending_ack_bytes()` | <1KB | >2KB |
| Connection | `lwip_ssl_is_connected()` | 1 (connected) | 0 (disconnected) |

**Use these functions together for complete connection monitoring!**
