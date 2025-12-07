# Quick Fix: TCP Buffer Full Error

## The Problem
```
tcp_write failed: -1
```
After sending 5 messages using persistent connection.

## The Cause
TCP send buffer is full. You're sending faster than the network can transmit.

## The Fix (3 Simple Steps)

### 1. Check Buffer Before Sending
```c
int available = lwip_tcp_get_send_buffer_available("conn1");
if (available < message_length) {
    // Wait for buffer space
    while (available < message_length) {
        lwip_poll();
        Sleep(50);
        available = lwip_tcp_get_send_buffer_available("conn1");
    }
}
```

### 2. Handle Return Code
```c
int result = lwip_tcp_send_persistent("conn1", data, len);
if (result == -2) {
    // Buffer full - retry
    Sleep(100);
    lwip_poll();
    result = lwip_tcp_send_persistent("conn1", data, len);
}
```

### 3. Always Call lwip_poll()
```c
for (int i = 0; i < 100; i++) {
    lwip_tcp_send_persistent(...);
    lwip_poll();  // REQUIRED!
    Sleep(10);    // Optional delay
}
```

## Complete Example

```c
// Connect once
lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
Sleep(100);

// Send with flow control
for (int i = 0; i < 100; i++) {
    uint8_t msg[100];
    int len = sprintf((char*)msg, "Message %d", i);
    
    // Check buffer
    int available = lwip_tcp_get_send_buffer_available("conn1");
    while (available < len) {
        lwip_poll();
        Sleep(50);
        available = lwip_tcp_get_send_buffer_available("conn1");
    }
    
    // Send
    int result = lwip_tcp_send_persistent("conn1", msg, len);
    if (result == -2) {
        // Retry once
        Sleep(100);
        lwip_poll();
        result = lwip_tcp_send_persistent("conn1", msg, len);
    }
    
    // Process network
    lwip_poll();
    Sleep(10);
}

// Disconnect
lwip_tcp_disconnect_persistent("conn1");
```

## New API Functions

```c
// Check available send buffer space (in bytes)
int lwip_tcp_get_send_buffer_available(const char* id);
// Returns: available bytes, or -1 on error

// Send with buffer check (updated)
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len);
// Returns:
//   0  = Success
//  -1  = Fatal error
//  -2  = Buffer full (retry later)
```

## Why This Happens

```
Default TCP send buffer: ~2-4 KB
Your messages: 100 bytes each
After ~20-40 fast sends: BUFFER FULL

Solution: Wait for buffer to drain (ACKs received)
```

## Key Rules

1. **Always** call `lwip_poll()` after sending
2. **Check** buffer space before sending large amounts
3. **Retry** if you get return code -2
4. **Add delay** between sends if needed (10-100ms)
5. **Process packets** - call `lwip_process_packet()` when data arrives

## Still Having Issues?

### Option 1: Reduce Send Rate
```c
Sleep(50);  // Instead of Sleep(10)
```

### Option 2: Increase Buffer (in lwipopts.h)
```c
#define TCP_SND_BUF (16384)  // 16KB instead of default
```

### Option 3: Split Large Messages
```c
const int CHUNK_SIZE = 512;
for (int offset = 0; offset < total_len; offset += CHUNK_SIZE) {
    int chunk = MIN(CHUNK_SIZE, total_len - offset);
    send_with_flow_control(..., data + offset, chunk);
}
```

## Documentation
- Full guide: `docs/FIXING_BUFFER_FULL_ERROR.md`
- Working example: `docs/working_example_flow_control.c`
