# Fixing TCP Send Buffer Full Error (tcp_write failed: -1)

## Problem
When using persistent TCP connections and sending messages rapidly, you get:
```
tcp_write failed: -1
```

**Error Code**: `-1` = `ERR_MEM` in LwIP
**Cause**: TCP send buffer is full

## Why This Happens

### TCP Send Buffer Behavior
```
Your App               LwIP TCP Buffer              Network
   |                         |                          |
   |--send msg 1------------>|                          |
   |--send msg 2------------>|                          |
   |--send msg 3------------>|                          |
   |--send msg 4------------>|                          |
   |--send msg 5------------>|                          |
   |--send msg 6---X         | <- BUFFER FULL          |
   |                         |                          |
   |                         |--------msg 1------------>|
   |                         |<--------ACK--------------|
   |                         | <- space freed           |
   |--retry msg 6----------->|                          |
```

**Default TCP_SND_BUF size**: Usually 2-8 KB
**Problem**: You're sending faster than the network can transmit and receive ACKs

## Solutions

### Solution 1: Check Buffer Before Sending (Recommended)

```c
// Good: Check buffer availability first
int send_with_flow_control(const char* id, const uint8_t* data, int len) {
    // Check available buffer space
    int available = lwip_tcp_get_send_buffer_available(id);
    
    if (available < len) {
        // Buffer full - wait and retry
        printf("Buffer full, waiting... (need %d, available %d)\n", len, available);
        
        // Give LwIP time to send data and free buffer
        for (int i = 0; i < 10; i++) {
            lwip_poll();  // Process LwIP
            Sleep(10);    // Small delay
            
            available = lwip_tcp_get_send_buffer_available(id);
            if (available >= len) {
                break;  // Buffer freed, can send now
            }
        }
        
        if (available < len) {
            printf("ERROR: Buffer still full after waiting\n");
            return -1;
        }
    }
    
    // Now send (should succeed)
    return lwip_tcp_send_persistent(id, data, len);
}

// Usage
for (int i = 0; i < 100; i++) {
    uint8_t msg[100];
    sprintf((char*)msg, "Message %d", i);
    
    int result = send_with_flow_control("conn1", msg, strlen((char*)msg));
    if (result < 0) {
        printf("Failed to send message %d\n", i);
    }
    
    lwip_poll();  // Always call lwip_poll to process network
}
```

### Solution 2: Handle Return Code and Retry

The updated `lwip_tcp_send_persistent()` now returns:
- `0` = Success
- `-1` = Fatal error
- `-2` = Buffer full (retry later)

```c
int send_with_retry(const char* id, const uint8_t* data, int len) {
    const int MAX_RETRIES = 10;
    
    for (int retry = 0; retry < MAX_RETRIES; retry++) {
        int result = lwip_tcp_send_persistent(id, data, len);
        
        if (result == 0) {
            return 0;  // Success
        }
        else if (result == -2) {
            // Buffer full - wait and retry
            printf("Buffer full, retry %d/%d\n", retry + 1, MAX_RETRIES);
            lwip_poll();
            Sleep(50);  // Wait for buffer to free up
            continue;
        }
        else {
            // Fatal error
            return -1;
        }
    }
    
    printf("ERROR: Failed after %d retries\n", MAX_RETRIES);
    return -1;
}
```

### Solution 3: Add Delay Between Sends

```c
// Simple: Just add delay between sends
lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);

for (int i = 0; i < 100; i++) {
    uint8_t msg[100];
    sprintf((char*)msg, "Message %d", i);
    
    lwip_tcp_send_persistent("conn1", msg, strlen((char*)msg));
    
    lwip_poll();  // Process network
    Sleep(10);    // Small delay to let buffer drain
}

lwip_tcp_disconnect_persistent("conn1");
```

### Solution 4: Use Sent Callback (Advanced)

```c
typedef struct {
    int messages_in_flight;
    int max_in_flight;
} flow_control_t;

flow_control_t flow_ctrl = { 0, 5 };

void my_send_complete_callback(void) {
    flow_ctrl.messages_in_flight--;
    printf("Message sent, in flight: %d\n", flow_ctrl.messages_in_flight);
}

// Create connection with callback
lwip_create_connection("conn1", "192.168.1.100", "255.255.255.0", "192.168.1.1",
                      udp_callback, my_send_complete_callback);

lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);

for (int i = 0; i < 100; i++) {
    // Wait if too many messages in flight
    while (flow_ctrl.messages_in_flight >= flow_ctrl.max_in_flight) {
        lwip_poll();
        Sleep(10);
    }
    
    uint8_t msg[100];
    sprintf((char*)msg, "Message %d", i);
    
    if (lwip_tcp_send_persistent("conn1", msg, strlen((char*)msg)) == 0) {
        flow_ctrl.messages_in_flight++;
    }
    
    lwip_poll();
}

lwip_tcp_disconnect_persistent("conn1");
```

## Complete Working Example

```c
#include "lwip_wrapper.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

void udp_cb(uint8_t* data, int len) {
    // Handle outgoing packets
}

void send_complete_cb(void) {
    printf("Message sent\n");
}

int main() {
    lwip_init_stack_global();
    
    // Create connection
    lwip_create_connection("conn1", "192.168.1.100", "255.255.255.0", "192.168.1.1",
                          udp_cb, send_complete_cb);
    
    // Connect persistent
    lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
    lwip_poll();
    Sleep(100);  // Wait for connection
    
    // Send 100 messages with proper flow control
    for (int i = 0; i < 100; i++) {
        uint8_t msg[100];
        int msg_len = sprintf((char*)msg, "Message %d", i);
        
        // Check buffer availability
        int available = lwip_tcp_get_send_buffer_available("conn1");
        printf("Sending message %d (buffer available: %d bytes)\n", i, available);
        
        // Wait if buffer is too full
        while (available < msg_len) {
            printf("Buffer full, waiting...\n");
            lwip_poll();
            Sleep(50);
            available = lwip_tcp_get_send_buffer_available("conn1");
        }
        
        // Send message
        int result = lwip_tcp_send_persistent("conn1", msg, msg_len);
        if (result == -2) {
            // Buffer full, wait and retry
            printf("Buffer full, retrying...\n");
            lwip_poll();
            Sleep(100);
            result = lwip_tcp_send_persistent("conn1", msg, msg_len);
        }
        
        if (result < 0) {
            printf("ERROR: Failed to send message %d\n", i);
            break;
        }
        
        // CRITICAL: Always call lwip_poll after sending
        lwip_poll();
        
        // Optional: small delay between messages
        Sleep(10);
    }
    
    // Disconnect
    lwip_tcp_disconnect_persistent("conn1");
    lwip_poll();
    
    // Cleanup
    lwip_close_connection("conn1");
    
    return 0;
}
```

## Key Points

### 1. Always Call lwip_poll()
```c
lwip_tcp_send_persistent(...);
lwip_poll();  // REQUIRED - processes network and frees buffer
```

### 2. Check Buffer Availability
```c
int available = lwip_tcp_get_send_buffer_available("conn1");
if (available < message_length) {
    // Wait or retry
}
```

### 3. Handle Return Codes
```c
int result = lwip_tcp_send_persistent(...);
if (result == -2) {
    // Buffer full - retry
} else if (result < 0) {
    // Fatal error
}
```

### 4. Add Delays if Needed
```c
lwip_tcp_send_persistent(...);
lwip_poll();
Sleep(10);  // Give network time to transmit
```

## Troubleshooting

### Still Getting Errors?

**1. Increase lwip_poll() frequency**
```c
// Bad
for (int i = 0; i < 100; i++) {
    send(...);
}
lwip_poll();  // Too late!

// Good
for (int i = 0; i < 100; i++) {
    send(...);
    lwip_poll();  // After each send
}
```

**2. Reduce message size or rate**
```c
// If messages are large
const int MAX_CHUNK = 1024;
for (int offset = 0; offset < total_len; offset += MAX_CHUNK) {
    int chunk_len = MIN(MAX_CHUNK, total_len - offset);
    send_with_flow_control(..., data + offset, chunk_len);
    lwip_poll();
}
```

**3. Check network speed**
```c
// Slow network? Reduce send rate
Sleep(50);  // Increase delay between sends
```

**4. Increase TCP_SND_BUF (in lwipopts.h)**
```c
// Default: 2048 or 4096
#define TCP_SND_BUF (16384)  // Increase to 16KB
```

## Summary

| Issue | Solution |
|-------|----------|
| Buffer full after 5 sends | Check buffer before sending |
| Need to send fast | Use flow control with retry |
| Large messages | Split into chunks |
| Slow network | Add delays between sends |
| Always | Call `lwip_poll()` regularly |

The key is **flow control**: don't send faster than the network can handle!
