# SSL ACK Queue - Quick Troubleshooting Guide

Since you're already calling `lwip_poll()` regularly, here are other things to check if your ACK queue is still growing:

---

## 1. Quick Health Check

Add this to your code to monitor queue health:

```c
// Call this every 1-2 seconds
void check_ack_queue_health(const char* conn_id) {
    int pending = lwip_ssl_get_pending_ack_count(conn_id);
    
    if (pending > 15) {
        printf("WARNING: High ACK queue: %d messages\n", pending);
        lwip_ssl_print_ack_queue_state(conn_id);
    }
}
```

---

## 2. Common Issues (Even With `lwip_poll()`)

### Issue A: Polling Too Slowly
```c
// BAD: Only 2 Hz
while (running) {
    lwip_poll();
    Sleep(500);  // Too slow!
}

// GOOD: 20 Hz
while (running) {
    lwip_poll();
    Sleep(50);   // Fast enough
}
```

### Issue B: Sending Too Fast
```c
// BAD: No rate limiting
for (int i = 0; i < 1000; i++) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
}

// GOOD: Check queue before sending
for (int i = 0; i < 1000; i++) {
    // Wait if queue is too large
    while (lwip_ssl_get_pending_ack_count(id) > 15) {
        Sleep(10);
    }
    lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

### Issue C: Network Too Slow
If your network has high latency (>100ms), ACKs take longer to arrive:

```c
// Adjust MAX_PENDING based on network latency
// High latency network: allow more pending
#define MAX_PENDING_ACKS 30  // Instead of 15

// Or add delays between sends
lwip_ssl_send_persistent(id, data, len, msg_id);
Sleep(20);  // Give network time to ACK
```

### Issue D: Large Messages
Large messages take more TCP segments ? more time to ACK:

```c
// Check bytes, not just message count
int pending_bytes = lwip_ssl_get_pending_ack_bytes(id);
if (pending_bytes > 5000) {  // ~2 TCP send buffers
    printf("Waiting for %d bytes to be ACK'd\n", pending_bytes);
    Sleep(50);
}
```

---

## 3. Diagnostic Functions

### Get Pending Count
```c
int pending = lwip_ssl_get_pending_ack_count("my_ssl_conn");
printf("Pending ACKs: %d\n", pending);
```

### Get Pending Bytes
```c
int pending_bytes = lwip_ssl_get_pending_ack_bytes("my_ssl_conn");
printf("Pending bytes: %d\n", pending_bytes);
```

### Print Detailed State
```c
lwip_ssl_print_ack_queue_state("my_ssl_conn");
```

Output example:
```
=== SSL ACK Queue Status for 'my_ssl_conn' ===
Connection state: 2 (0=CONNECTING, 2=CONNECTED)
Connection mode: 1 (0=SINGLE_SEND, 1=PERSISTENT)
Total messages sent: 250

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

## 4. Recommended Pattern

```c
// Monitoring thread (separate from poll thread)
DWORD WINAPI monitor_thread(LPVOID param) {
    const char* conn_id = (const char*)param;
    
    while (running) {
        int pending = lwip_ssl_get_pending_ack_count(conn_id);
        
        if (pending > 20) {
            printf("ALARM: ACK queue too large: %d\n", pending);
            lwip_ssl_print_ack_queue_state(conn_id);
        }
        
        Sleep(1000);  // Check every second
    }
    return 0;
}

// Safe send function with backpressure
int safe_send(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Wait if queue is full
    int pending = lwip_ssl_get_pending_ack_count(id);
    if (pending > 20) {
        printf("Waiting for ACKs (queue: %d)...\n", pending);
        
        int wait_count = 0;
        while (pending > 15 && wait_count < 100) {
            Sleep(50);
            pending = lwip_ssl_get_pending_ack_count(id);
            wait_count++;
        }
        
        if (pending > 20) {
            printf("ERROR: Queue still full after waiting\n");
            return -3;  // Reject send
        }
    }
    
    // Now safe to send
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

---

## 5. Testing Your Setup

### Test 1: Burst Send
Send 100 messages as fast as possible, monitor queue:

```c
for (int i = 0; i < 100; i++) {
    char msg_id[32];
    sprintf(msg_id, "test_%d", i);
    
    lwip_ssl_send_persistent(id, data, len, msg_id);
    
    if (i % 10 == 0) {
        int pending = lwip_ssl_get_pending_ack_count(id);
        printf("Sent %d, queue: %d\n", i, pending);
    }
}

// Queue should drain
Sleep(2000);
int final_pending = lwip_ssl_get_pending_ack_count(id);
printf("Final queue: %d (should be 0)\n", final_pending);
```

**Expected**: Queue peaks at 10-30, then drains to 0  
**Problem**: Queue keeps growing past 50

### Test 2: ACK Callback Test
Verify ACKs are arriving:

```c
volatile int acks_received = 0;

void my_ack_callback(const char* msg_id) {
    acks_received++;
    printf("ACK #%d: %s\n", acks_received, msg_id);
}

// Send 10 messages
for (int i = 0; i < 10; i++) {
    char msg_id[32];
    sprintf(msg_id, "ack_test_%d", i);
    lwip_ssl_send_persistent(id, data, len, msg_id);
}

// Wait for ACKs
Sleep(2000);
printf("Sent: 10, Received ACKs: %d\n", acks_received);
```

**Expected**: Received ACKs = 10  
**Problem**: Received ACKs < 10 ? ACKs not being processed

---

## 6. Root Cause Checklist

If queue is still growing, check:

- [ ] `lwip_poll()` is called every 50ms or faster
- [ ] ACK callback is properly registered in `lwip_ssl_connect_persistent()`
- [ ] `tcp_sent()` callback is set in `ssl_tcp_connected_cb()`
- [ ] Not sending too fast (>100 msg/sec sustained)
- [ ] Network latency is reasonable (<200ms)
- [ ] Messages aren't too large (>1KB each)
- [ ] TCP send buffer isn't constantly full
- [ ] Remote host is actually ACKing packets

---

## 7. Emergency Fixes

### Stop Sending Temporarily
```c
// Let queue drain completely
printf("Pausing sends to drain queue...\n");
Sleep(5000);
int remaining = lwip_ssl_get_pending_ack_count(id);
printf("Queue after pause: %d\n", remaining);
```

### Force Rate Limit
```c
// Add aggressive delay
lwip_ssl_send_persistent(id, data, len, msg_id);
Sleep(100);  // Force 10 msg/sec max
```

### Restart Connection
```c
// If queue is hopelessly stuck
if (lwip_ssl_get_pending_ack_count(id) > 100) {
    printf("Queue stuck, restarting connection...\n");
    lwip_ssl_disconnect_persistent(id);
    // Wait for cleanup
    Sleep(1000);
    // Reconnect
    lwip_ssl_connect_persistent(id, ip, port, hostname, ...);
}
```

---

## Summary

**You're calling `lwip_poll()` regularly ?**

**Next steps:**
1. Add monitoring with `lwip_ssl_get_pending_ack_count()`
2. Implement backpressure (wait if queue > 15-20)
3. Add delays between sends if needed
4. Use `lwip_ssl_print_ack_queue_state()` to debug
5. Verify ACK callbacks are being called

**Most likely causes if still growing:**
- Sending too fast (>50 msg/sec burst)
- Network latency too high
- Messages too large
- Not enough delays between sends

**Quick fix:**
```c
// Add this before every send
while (lwip_ssl_get_pending_ack_count(id) > 15) {
    Sleep(10);
}
```

This prevents queue from growing past 15 messages.
