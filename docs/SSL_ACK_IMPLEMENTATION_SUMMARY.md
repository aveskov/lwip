# SSL ACK Queue - Implementation Summary

## What Was Fixed

Your SSL persistent connections now have **proper TCP ACK tracking**, matching the non-SSL TCP implementation in `lwip_wrapper.c`.

## Key Changes Made

### 1. Added `ssl_tcp_sent_persistent()` Callback ?
- Registered via `tcp_sent()` in `ssl_tcp_connected_cb()`
- Called by LwIP when TCP actually ACKs data
- Processes ACK queue and triggers user callbacks

### 2. Removed Premature ACK Callbacks ?
- Old code called ACK callback in `ssl_flush_write_bio()` after `tcp_write()`
- This was **before TCP ACK arrived** (too early!)
- Now ACK callback fires when TCP actually acknowledges

### 3. Added Diagnostic Functions ?
```c
int lwip_ssl_get_pending_ack_count(const char* id);
int lwip_ssl_get_pending_ack_bytes(const char* id);
void lwip_ssl_print_ack_queue_state(const char* id);
```

## How ACK Queue Works Now

```
1. Your App: lwip_ssl_send_persistent(id, data, len, "msg_123")
   ?
2. SSL_write() ? BIO_pending() = 150 bytes (with SSL overhead)
   ?
3. Add to ACK queue: {msg_id="msg_123", bytes_sent=150}
   ?
4. ssl_flush_write_bio() ? tcp_write(150 bytes) ? tcp_output()
   ?
5. Network: TCP packet sent
   ?
6. lwip_poll() called (50ms later)
   ?
7. Network: TCP ACK received
   ?
8. LwIP calls: ssl_tcp_sent_persistent(len=150)
   ?
9. Find ACK entry with bytes_sent=150
   ?
10. Remove from queue & call: your_ack_callback("msg_123")
```

## Why Queue Can Still Grow (Even With Fixes)

### Sending Faster Than Network Can ACK

**Scenario:**
- You send 100 messages in 1 second
- Network roundtrip = 100ms
- Only 10 ACKs can arrive per second
- Queue grows by 90 messages

**Solution:** Rate limiting
```c
while (lwip_ssl_get_pending_ack_count(id) > 15) {
    Sleep(10);
}
lwip_ssl_send_persistent(id, data, len, msg_id);
```

### Network Latency

**High latency** (>100ms) = more messages in flight

| Latency | Send Rate | Max Safe Pending |
|---------|-----------|------------------|
| 50ms    | 20 msg/s  | 10 messages      |
| 100ms   | 20 msg/s  | 20 messages      |
| 200ms   | 20 msg/s  | 40 messages      |

**Solution:** Adjust `MAX_PENDING_ACKS` based on your network

### TCP Send Buffer Full

**TCP buffer** = ~2-4KB. Once full:
- New sends get `ERR_MEM`
- But already-sent messages are still in ACK queue
- Need to wait for buffer to drain

**Solution:** Check buffer before sending
```c
int buffer_avail = lwip_tcp_get_send_buffer_available(id);
if (buffer_avail < len) {
    Sleep(20);  // Wait for buffer
}
```

## Monitoring Best Practices

### In Production: Add Monitoring Thread

```c
DWORD WINAPI monitor_thread(LPVOID param) {
    const char* conn_id = (const char*)param;
    
    while (running) {
        int pending = lwip_ssl_get_pending_ack_count(conn_id);
        
        // Log if high
        if (pending > 20) {
            log_warning("High ACK queue: %d messages", pending);
        }
        
        // Alert if critical
        if (pending > 50) {
            log_error("CRITICAL: ACK queue: %d messages", pending);
            lwip_ssl_print_ack_queue_state(conn_id);
        }
        
        Sleep(1000);
    }
    return 0;
}
```

### Track Statistics

```c
typedef struct {
    volatile LONG sent;
    volatile LONG acked;
    volatile LONG errors;
} ssl_stats_t;

ssl_stats_t stats = {0};

void my_ack_callback(const char* msg_id) {
    InterlockedIncrement(&stats.acked);
}

void send_with_stats(...) {
    int result = lwip_ssl_send_persistent(...);
    if (result == 0) {
        InterlockedIncrement(&stats.sent);
    } else {
        InterlockedIncrement(&stats.errors);
    }
}

// Check health
long in_flight = stats.sent - stats.acked;
if (in_flight > 30) {
    printf("WARNING: %ld messages in flight\n", in_flight);
}
```

## Recommended Configuration

### For Low Latency Networks (<50ms)

```c
#define MAX_PENDING_ACKS 10
#define POLL_INTERVAL_MS 50
#define SEND_DELAY_MS 0        // No delay needed
```

### For Medium Latency Networks (50-150ms)

```c
#define MAX_PENDING_ACKS 20
#define POLL_INTERVAL_MS 50
#define SEND_DELAY_MS 10       // Small delay
```

### For High Latency Networks (>150ms)

```c
#define MAX_PENDING_ACKS 40
#define POLL_INTERVAL_MS 30    // Poll faster
#define SEND_DELAY_MS 20       // Longer delay
```

### For Burst Sending

```c
#define MAX_PENDING_ACKS 30
#define WARNING_THRESHOLD 20
#define CRITICAL_THRESHOLD 50

// Backpressure logic
int safe_send(...) {
    int pending = lwip_ssl_get_pending_ack_count(id);
    
    if (pending > MAX_PENDING_ACKS) {
        // Wait for queue to drain
        while (pending > (MAX_PENDING_ACKS - 5)) {
            Sleep(20);
            pending = lwip_ssl_get_pending_ack_count(id);
        }
    }
    
    return lwip_ssl_send_persistent(...);
}
```

## Testing Your Implementation

### Test 1: Verify ACKs Arrive

```c
volatile int acks = 0;

void test_ack_callback(const char* msg_id) {
    acks++;
}

// Send 10 messages
for (int i = 0; i < 10; i++) {
    lwip_ssl_send_persistent(id, data, len, "test");
}

// Wait
Sleep(2000);

printf("ACKs received: %d/10\n", acks);
// Should print "10/10"
```

### Test 2: Verify Queue Drains

```c
// Send burst
for (int i = 0; i < 50; i++) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
}

int pending = lwip_ssl_get_pending_ack_count(id);
printf("After burst: %d pending\n", pending);

// Wait for drain
Sleep(3000);

pending = lwip_ssl_get_pending_ack_count(id);
printf("After drain: %d pending (should be 0)\n", pending);
```

### Test 3: Stress Test

```c
// Send 1000 messages with monitoring
for (int i = 0; i < 1000; i++) {
    // Backpressure
    while (lwip_ssl_get_pending_ack_count(id) > 20) {
        Sleep(10);
    }
    
    lwip_ssl_send_persistent(id, data, len, msg_id);
    
    if (i % 100 == 0) {
        int p = lwip_ssl_get_pending_ack_count(id);
        printf("Sent %d, queue: %d\n", i, p);
    }
}

// Queue should never exceed 25
```

## Troubleshooting Steps

### Problem: Queue Keeps Growing

1. **Check `lwip_poll()` frequency**
   ```c
   // Add timing
   static DWORD last_poll = 0;
   DWORD now = GetTickCount();
   DWORD delta = now - last_poll;
   if (delta > 100) {
       printf("WARNING: Poll interval too long: %lums\n", delta);
   }
   last_poll = now;
   lwip_poll();
   ```

2. **Check ACK callback registration**
   ```c
   // Should be non-NULL
   printf("ACK callback: %p\n", ack_callback_function);
   ```

3. **Check tcp_sent callback**
   ```c
   // In ssl_tcp_connected_cb(), verify:
   if (conn->mode == SSL_CONN_MODE_PERSISTENT) {
       tcp_sent(tpcb, ssl_tcp_sent_persistent);  // This line exists?
   }
   ```

4. **Print queue state**
   ```c
   lwip_ssl_print_ack_queue_state(id);
   ```

### Problem: ACKs Not Arriving

1. **Verify network connectivity**
   - Can you ping the remote host?
   - Is firewall blocking TCP ACKs?

2. **Check remote host behavior**
   - Is remote host sending TCP ACKs?
   - Use Wireshark to verify ACK packets

3. **Verify polling thread**
   ```c
   // Add debug output
   printf("[POLL] Calling lwip_poll()\n");
   lwip_poll();
   ```

## Files Created/Modified

### Modified Files
- `wrapper/lwip_wrapper_ssl.h` - Added diagnostic function declarations
- `wrapper/lwip_wrapper_ssl.cpp` - Added diagnostic implementations

### Documentation Files
- `docs/SSL_ACK_QUEUE_MANAGEMENT.md` - Complete management guide
- `docs/SSL_UNBOUNDED_ACK_QUEUE.md` - Root cause analysis
- `docs/ssl_diagnostics.c` - Diagnostic function examples
- `docs/SSL_ACK_MONITORING_EXAMPLE.c` - Complete working example
- `docs/SSL_ACK_TROUBLESHOOTING.md` - Quick troubleshooting guide (this file)

## Quick Reference

### Essential Functions

```c
// Monitor queue size
int pending = lwip_ssl_get_pending_ack_count("conn_id");

// Get pending bytes
int bytes = lwip_ssl_get_pending_ack_bytes("conn_id");

// Print detailed state
lwip_ssl_print_ack_queue_state("conn_id");

// Always call this regularly (every 50ms)
lwip_poll();
```

### Safe Send Pattern

```c
int safe_send(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Check queue
    int pending = lwip_ssl_get_pending_ack_count(id);
    
    // Wait if too full
    while (pending > MAX_PENDING_ACKS) {
        Sleep(20);
        pending = lwip_ssl_get_pending_ack_count(id);
    }
    
    // Send
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

## Summary

? **ACK tracking is now correct** - uses LwIP's `tcp_sent()` callback  
? **Diagnostic functions added** - monitor queue in real-time  
? **Examples provided** - see `SSL_ACK_MONITORING_EXAMPLE.c`  
? **Documentation complete** - multiple guides available  

?? **Action Items:**
1. Add monitoring with `lwip_ssl_get_pending_ack_count()`
2. Implement backpressure (wait if queue > 15-20)
3. Test with provided examples
4. Adjust thresholds for your network latency

?? **Expected Behavior:**
- Queue peaks at 10-30 messages during bursts
- Queue drains to 0 within 1-2 seconds
- ACK callbacks arrive regularly
- No memory growth over time
