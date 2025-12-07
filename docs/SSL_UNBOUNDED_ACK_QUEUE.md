# Unbounded ACK Queue Growth - Root Cause Analysis

## The Problem

When using `lwip_ssl_send_persistent()`, the pending ACK queue can grow unbounded if messages are sent faster than TCP can acknowledge them.

---

## Why This Happens

### 1. **TCP ACKs Take Time**

```
Your Code              LwIP              Network            Remote Host
   |                    |                   |                    |
   |-- send msg 1 ----->|                   |                    |
   |                    |--- TCP packet --->|------------------>|
   |-- send msg 2 ----->|                   |                    |
   |                    |--- TCP packet --->|------------------>|
   |-- send msg 3 ----->|                   |                    |
   |                    |--- TCP packet --->|------------------>|
   |                    |                   |<-------- TCP ACK --|
   |                    |<-- tcp_sent() ----| (ACK for msg 1)    |
   |<-- ACK callback ---|                   |                    |
   |                    |                   |<-------- TCP ACK --|
   |                    |<-- tcp_sent() ----| (ACK for msg 2)    |
   |<-- ACK callback ---|                   |                    |
```

**Time between send and ACK**: 10-200ms (depending on network)  
**Time to send message**: < 1ms  

**Result**: You can send 100+ messages before the first ACK arrives!

### 2. **TCP Send Buffer is Limited**

- Typical TCP send buffer: **2-4 KB**
- SSL overhead per message: **~50-100 bytes**
- Messages that fit in buffer: **20-80 messages**

Once buffer fills:
- New sends get `ERR_MEM` error
- But messages already sent are still in ACK queue
- Queue keeps growing until ACKs arrive

### 3. **Missing `lwip_poll()` Calls**

```c
// WRONG - ACKs never processed
for (int i = 0; i < 1000; i++) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
}
// ACK queue now has 1000 entries!

// RIGHT - Process ACKs regularly
for (int i = 0; i < 1000; i++) {
    lwip_ssl_send_persistent(id, data, len, msg_id);
    
    if (i % 10 == 0) {
        lwip_poll();  // Process incoming ACKs
        Sleep(10);
    }
}
```

`lwip_poll()` calls `sys_check_timeouts()` which:
- Processes incoming TCP ACK packets
- Triggers `tcp_sent()` callbacks
- Drains the ACK queue

**Without `lwip_poll()`**: ACKs arrive but are never processed ? queue never drains!

---

## How ACK Queue Works

### Normal Flow (Working Correctly)

```
1. lwip_ssl_send_persistent() called
   ??> SSL_write() ? creates SSL record
       ??> BIO_pending() = 150 bytes (SSL overhead)
           ??> Add to ACK queue: {msg_id="m1", bytes_sent=150}
               ??> ssl_flush_write_bio()
                   ??> tcp_write(150 bytes)
                       ??> TCP buffer: 2048 - 150 = 1898 bytes left

2. Network: TCP packet sent to remote

3. Network: TCP ACK received (50ms later)

4. lwip_poll() called
   ??> sys_check_timeouts()
       ??> tcp_input() processes ACK
           ??> tcp_sent() callback ? ssl_tcp_sent_persistent(len=150)
               ??> Find ACK entry with bytes_sent=150
                   ??> Call user callback("m1")
                       ??> Free ACK entry
                           ??> ACK queue: 0 entries
```

### Broken Flow (Unbounded Growth)

```
1. Send 100 messages in loop (< 1 second)
   ??> ACK queue: 100 entries
       ??> TCP buffer: FULL (ERR_MEM on send #25)

2. NO lwip_poll() called
   ??> ACKs arrive from network
       ??> But tcp_input() never called
           ??> tcp_sent() never triggered
               ??> ACK queue: still 100 entries

3. Eventually: Out of memory, crash
```

---

## Detection

### Symptom 1: Growing Memory Usage

```c
// Add this monitoring:
void check_ack_queue_health() {
    static int last_count = 0;
    int current_count = lwip_ssl_get_pending_ack_count("ssl_conn");
    
    if (current_count > last_count + 10) {
        printf("ALARM: ACK queue growing! %d -> %d\n", last_count, current_count);
    }
    
    last_count = current_count;
}
```

### Symptom 2: Callbacks Stop Coming

```c
// Track ACK callback timing
static DWORD last_ack_time = 0;

void my_ack_callback(const char* msg_id) {
    DWORD now = GetTickCount();
    DWORD delta = now - last_ack_time;
    
    if (delta > 5000) {
        printf("WARNING: No ACK for %d ms\n", delta);
    }
    
    last_ack_time = now;
}
```

### Symptom 3: ERR_MEM Errors

```c
int result = lwip_ssl_send_persistent(id, data, len, msg_id);
if (result == -1) {
    // Check if it's a buffer issue
    int buffer_avail = lwip_tcp_get_send_buffer_available(id);
    int pending_acks = lwip_ssl_get_pending_ack_count(id);
    
    printf("Send failed: buffer=%d, pending_acks=%d\n", buffer_avail, pending_acks);
    
    if (pending_acks > 50) {
        printf("ERROR: ACK queue unbounded growth detected!\n");
    }
}
```

---

## Solutions (In Priority Order)

### Solution 1: Call `lwip_poll()` Regularly ? CRITICAL

```c
// Main thread or dedicated polling thread:
while (running) {
    lwip_poll();
    Sleep(50);  // 20 Hz polling rate
}
```

**This is MANDATORY**. Without this, nothing else works.

### Solution 2: Rate Limiting

```c
#define MAX_PENDING_ACKS 20

int safe_send(const char* id, const uint8_t* data, int len, const char* msg_id) {
    // Wait if queue is full
    int pending = lwip_ssl_get_pending_ack_count(id);
    while (pending >= MAX_PENDING_ACKS) {
        lwip_poll();
        Sleep(10);
        pending = lwip_ssl_get_pending_ack_count(id);
    }
    
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
```

### Solution 3: Enforce Queue Limit in Code

Modify `lwip_ssl_send_persistent()`:

```cpp
// Before sending, check queue size
int pending_count = 0;
pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
while (entry) {
    pending_count++;
    entry = entry->next;
}

if (pending_count >= MAX_ACK_QUEUE_SIZE) {
    printf("ERROR: ACK queue limit reached (%d)\n", pending_count);
    ssl_conn_unref(conn);
    return -3;  // Queue full, reject send
}
```

### Solution 4: Separate Polling Thread

```c
DWORD WINAPI poll_thread(LPVOID param) {
    while (running) {
        lwip_poll();
        Sleep(50);
    }
    return 0;
}

// Start in main:
CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
```

---

## Testing Your Fix

### Test 1: Burst Send Test

```c
void test_burst_send() {
    printf("Sending 1000 messages...\n");
    
    for (int i = 0; i < 1000; i++) {
        char msg_id[32];
        sprintf(msg_id, "msg_%d", i);
        
        int result = lwip_ssl_send_persistent(id, data, len, msg_id);
        
        if (i % 100 == 0) {
            int pending = lwip_ssl_get_pending_ack_count(id);
            printf("Sent %d, pending ACKs: %d\n", i, pending);
        }
        
        // CRITICAL: Process ACKs
        if (i % 10 == 0) {
            lwip_poll();
        }
    }
    
    // Wait for all ACKs
    int pending;
    while ((pending = lwip_ssl_get_pending_ack_count(id)) > 0) {
        printf("Waiting for ACKs: %d remaining\n", pending);
        lwip_poll();
        Sleep(100);
    }
    
    printf("All ACKs received!\n");
}
```

### Test 2: Monitor Queue Over Time

```c
void monitor_ack_queue() {
    while (running) {
        int count = lwip_ssl_get_pending_ack_count(id);
        int bytes = lwip_ssl_get_pending_ack_bytes(id);
        int tcp_buffer = lwip_tcp_get_send_buffer_available(id);
        
        printf("[%s] ACKs: %d (%d bytes), TCP buffer: %d\n",
               timestamp(), count, bytes, tcp_buffer);
        
        Sleep(1000);
    }
}
```

---

## Common Mistakes

### ? Mistake 1: Only Calling `lwip_poll()` When Sending

```c
// WRONG
int result = lwip_ssl_send_persistent(id, data, len, msg_id);
lwip_poll();  // Only called once per send
```

**Problem**: ACKs arrive asynchronously. Need continuous polling.

**Fix**: Call `lwip_poll()` in separate thread or main loop.

### ? Mistake 2: Assuming Send Success Means ACK'd

```c
// WRONG
if (lwip_ssl_send_persistent(id, data, len, msg_id) == 0) {
    printf("Message ACK'd\n");  // NO! Just sent to TCP buffer
}
```

**Fix**: Wait for ACK callback.

### ? Mistake 3: No Backpressure

```c
// WRONG
while (has_data()) {
    send_message();  // Unbounded sending
}
```

**Fix**: Check queue size, add delays.

---

## Summary Checklist

- [ ] **Call `lwip_poll()` every 50ms** (mandatory!)
- [ ] **Monitor ACK queue size**
- [ ] **Limit pending ACKs to 20-50**
- [ ] **Check TCP buffer before sending**
- [ ] **Add delays between sends**
- [ ] **Implement backpressure**
- [ ] **Test with burst sends**
- [ ] **Monitor queue in production**

---

## If All Else Fails

**Emergency queue drain**:

```c
void drain_ack_queue() {
    printf("EMERGENCY: Draining ACK queue\n");
    
    // Stop all sends
    stop_sending = 1;
    
    // Aggressive polling
    for (int i = 0; i < 200; i++) {
        lwip_poll();
        Sleep(10);
        
        int remaining = lwip_ssl_get_pending_ack_count(id);
        printf("Remaining ACKs: %d\n", remaining);
        
        if (remaining == 0) {
            printf("Queue drained successfully\n");
            break;
        }
    }
}
```

---

**Bottom Line**: If ACK queue grows unbounded, you're sending faster than the network can handle. **Call `lwip_poll()` regularly** and **add rate limiting**!
