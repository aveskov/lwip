# SSL ACK Queue Management Guide

## Problem: Unbounded ACK Queue Growth

If your ACK queue grows unbounded, it means **messages are being sent faster than TCP can acknowledge them**. This document explains causes and solutions.

---

## Root Causes

### 1. **Not Calling `lwip_poll()` Regularly**
**CRITICAL**: You MUST call `lwip_poll()` every 10-100ms

```c
// In your main loop or timer:
while (running) {
    lwip_poll();  // Process TCP ACKs and timers
    Sleep(50);    // 50ms interval
}
```

**Why**: `lwip_poll()` processes:
- Incoming TCP ACK packets
- TCP retransmissions
- TCP timeouts
- Without it, ACKs never get processed ? queue grows forever

### 2. **Sending Faster Than Network Can Handle**
TCP has limited send buffer (typically 2-4KB). If you send too fast:
```c
// BAD: Tight loop sending
for (int i = 0; i < 1000; i++) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

**Solution**: Check available buffer space:
```c
// GOOD: Check buffer before sending
int available = lwip_tcp_get_send_buffer_available(id);
if (available >= len) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
} else {
    // Wait for ACKs
    lwip_poll();
    Sleep(10);
}
```

### 3. **Network Issues**
- Packet loss ? retransmissions ? slow ACKs
- High latency network
- Receiver too slow to acknowledge

---

## Diagnostic Functions

### Add Queue Size Monitoring

```cpp
// Add to ssl_connection_entry_t:
int pending_ack_count;  // Track queue size

// Add diagnostic function:
int lwip_ssl_get_pending_ack_count(const char* id) {
    ssl_connection_entry_t* conn = find_ssl_connection(id);
    if (!conn) return -1;
    
    ssl_lock();
    int count = 0;
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        count++;
        entry = entry->next;
    }
    ssl_unlock();
    
    ssl_conn_unref(conn);
    return count;
}
```

### Monitor in Your Application

```c
// Check queue size regularly
int queue_size = lwip_ssl_get_pending_ack_count("ssl_conn");
if (queue_size > 10) {
    printf("WARNING: ACK queue has %d pending messages\n", queue_size);
    // Slow down sending
    Sleep(100);
}
```

---

## Solutions

### Solution 1: Add Rate Limiting

```c
#define MAX_PENDING_ACKS 10

int send_with_backpressure(const char* id, const uint8_t* data, int len, const char* msg_id) {
    int pending = lwip_ssl_get_pending_ack_count(id);
    
    while (pending >= MAX_PENDING_ACKS) {
        // Too many pending - wait for ACKs
        lwip_poll();
        Sleep(50);
        pending = lwip_ssl_get_pending_ack_count(id);
    }
    
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

### Solution 2: Add Queue Size Limit in Code

```cpp
// In lwip_ssl_send_persistent(), add check:
int lwip_ssl_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id) {
    // ... existing checks ...
    
    // Check pending ACK queue size
    ssl_lock();
    int pending_count = 0;
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        pending_count++;
        entry = entry->next;
    }
    ssl_unlock();
    
    if (pending_count > 20) {  // Configurable limit
        printf("ERROR: Too many pending ACKs (%d), send rejected\n", pending_count);
        ssl_conn_unref(conn);
        return -3;  // Queue full
    }
    
    // ... rest of function ...
}
```

### Solution 3: Implement Callback-Based Flow Control

```c
// Track in-flight messages
volatile int in_flight_messages = 0;

void my_ack_callback(const char* message_id) {
    InterlockedDecrement(&in_flight_messages);
    printf("ACK received for: %s (in_flight=%d)\n", message_id, in_flight_messages);
}

int send_with_flow_control(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Wait if too many in flight
    while (in_flight_messages >= 10) {
        lwip_poll();
        Sleep(10);
    }
    
    InterlockedIncrement(&in_flight_messages);
    int result = lwip_ssl_send_persistent(id, data, len, msg_id);
    
    if (result != 0) {
        // Failed - decrement
        InterlockedDecrement(&in_flight_messages);
    }
    
    return result;
}
```

---

## Code Fixes Needed

### Fix 1: Ensure `tcp_sent` Callback is Set

```cpp
// In ssl_tcp_connected_cb():
if (conn->mode == SSL_CONN_MODE_PERSISTENT) {
    lwip_lock();
    tcp_sent(tpcb, ssl_tcp_sent_persistent);  // MUST be set!
    lwip_unlock();
}
```

### Fix 2: Correct Byte Tracking

```cpp
// In lwip_ssl_send_persistent():
// CRITICAL: Track ACTUAL TCP bytes (with SSL overhead)
int bio_pending_before = BIO_pending(conn->wbio);
int bytes_written = SSL_write(conn->ssl, data, len);
int bio_pending_after = BIO_pending(conn->wbio);

// Bytes to track = new data in BIO
int tcp_bytes = bio_pending_after - bio_pending_before;
ack_entry->bytes_sent = (u16_t)tcp_bytes;
```

### Fix 3: Handle SSL Fragmentation

SSL may split your data into multiple records. Each record needs separate tracking:

```cpp
// Better approach: Track BIO output size
int total_tcp_bytes = 0;
while (BIO_pending(conn->wbio) > 0) {
    // Read and send each chunk
    int read_bytes = BIO_read(conn->wbio, buf, sizeof(buf));
    tcp_write(conn->pcb, buf, read_bytes, TCP_WRITE_FLAG_COPY);
    total_tcp_bytes += read_bytes;
}
ack_entry->bytes_sent = (u16_t)total_tcp_bytes;
```

---

## Testing Recommendations

### Test 1: High-Rate Send Test
```c
// Send 1000 messages as fast as possible
for (int i = 0; i < 1000; i++) {
    char msg_id[32];
    sprintf(msg_id, "msg_%d", i);
    
    int result = lwip_ssl_send_persistent(id, data, len, msg_id);
    if (result == -3) {
        printf("Queue full at message %d\n", i);
        break;
    }
    
    // Process ACKs periodically
    if (i % 10 == 0) {
        lwip_poll();
    }
}
```

### Test 2: Monitor Queue Growth
```c
// In separate monitoring thread:
while (running) {
    int queue_size = lwip_ssl_get_pending_ack_count("ssl_conn");
    int buffer_avail = lwip_tcp_get_send_buffer_available("base_conn");
    
    printf("ACK queue: %d, TCP buffer: %d bytes\n", queue_size, buffer_avail);
    
    Sleep(1000);
}
```

---

## Emergency Recovery

If queue grows too large, you can forcibly drain it:

```c
void emergency_drain_ack_queue(const char* id) {
    // Stop sending new messages
    
    // Process ACKs aggressively
    for (int i = 0; i < 100; i++) {
        lwip_poll();
        Sleep(10);
        
        int remaining = lwip_ssl_get_pending_ack_count(id);
        if (remaining == 0) break;
        
        printf("Draining ACK queue: %d remaining\n", remaining);
    }
}
```

---

## Summary Checklist

? **Call `lwip_poll()` every 50-100ms**  
? **Monitor ACK queue size**  
? **Add rate limiting (max 10-20 pending ACKs)**  
? **Check TCP send buffer before sending**  
? **Verify `tcp_sent()` callback is registered**  
? **Track correct TCP byte counts (with SSL overhead)**  
? **Handle SSL fragmentation properly**  
? **Test under high load**  

---

## Additional Resources

- See `docs/TCP_PERFORMANCE_OPTIMIZATION.md` for buffer management
- See `docs/FIXING_BUFFER_FULL_ERROR.md` for flow control patterns
- See non-SSL TCP implementation in `wrapper/lwip_wrapper.c` for reference
