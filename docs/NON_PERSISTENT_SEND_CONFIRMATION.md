n# Non-Persistent Mode: How to Know When Message is Sent

## Problem Statement

In non-persistent SSL mode, how do you know when your message has been sent without a callback?

## Solution: NOW WITH CALLBACK! 

**Good news:** The API has been updated. Non-persistent mode **now supports** an optional `send_complete_callback`.

## Updated API

```c
int lwip_ssl_connect(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,
                     ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_complete_callback_t send_complete_cb);  // ? NOW AVAILABLE!
```

## Usage Options

### Option 1: With Callback (Recommended)

```c
void on_send_complete(void) {
    printf("Message sent! Can proceed...\n");
    // Continue with next operation
    send_next_request();
}

// Connect with callback
lwip_ssl_connect("conn1", "192.168.1.50", 443, "example.com",
                 on_handshake,
                 NULL,              // data_received (optional)
                 on_send_complete); // ? Provides feedback

// Send data
lwip_ssl_send_data("conn1", data, len);
// ? on_send_complete() will be called when SSL_write succeeds
```

### Option 2: Without Callback (Simple)

```c
// Connect without callback (pass NULL)
lwip_ssl_connect("conn1", "192.168.1.50", 443, "example.com",
                 on_handshake,
                 NULL,   // data_received
                 NULL);  // ? No callback needed

// Send data - blocks until queued
int result = lwip_ssl_send_data("conn1", data, len);
if (result == 0) {
    printf("Message queued successfully\n");
    // Data is queued in TCP send buffer
    // Will be sent when lwip_poll() processes
}
```

### Option 3: Synchronous Check (Polling)

If you don't use callbacks, you can check the return value:

```c
int result = lwip_ssl_send_data("conn1", data, len);

if (result == 0) {
    // Success - data queued for sending
    printf("Message queued in TCP buffer\n");
    
    // Ensure it gets sent
    lwip_poll();  // Process LwIP events
    
    // Optional: wait a bit for network processing
    Sleep(10);
    
} else if (result == -1) {
    // Fatal error
    printf("Send failed!\n");
} else {
    // Other error
    printf("Unexpected error\n");
}
```

## Callback Timing

### When is `send_complete_callback` called?

```
Timeline for Non-Persistent Mode:

0ms:   lwip_ssl_send_data(data)
       ?
       SSL_write(data) ? encrypt ? write to BIO
       ?
1ms:   ssl_flush_write_bio() ? tcp_write() ? tcp_output()
       ?
       ? send_complete_callback() ? CALLED HERE
       ?
2ms:   return 0 to caller
       ?
       [Connection closes automatically]
       ?
50ms:  TCP ACK arrives (no callback in non-persistent mode)
```

**Key Point:** Callback fires **immediately** after `SSL_write()` succeeds, NOT when TCP ACKs.

## Comparison: Persistent vs Non-Persistent Callbacks

### Non-Persistent Mode
```c
lwip_ssl_connect(..., on_send_complete);
// one callback: send_complete

lwip_ssl_send_data(...);
// ? on_send_complete() fires immediately
// ? Connection closes
// ? No ACK callback
```

### Persistent Mode
```c
lwip_ssl_connect_persistent(..., 
                            on_send_complete,  // immediate
                            on_ack_complete);  // later
// two callbacks: send_complete AND ack_complete

lwip_ssl_send_persistent(..., "msg1");
// ? on_send_complete() fires immediately (can send next)
// ? Later: on_ack_complete("msg1") fires when TCP ACKs
```

## Complete Examples

### Example 1: Simple One-Shot Request

```c
// Global state
int message_sent = 0;

void on_send_complete(void) {
    message_sent = 1;
    printf("Request sent to server\n");
}

void send_api_request(void) {
    // Connect
    lwip_ssl_connect("api_conn", "api.example.com", 443, "api.example.com",
                     NULL,              // handshake callback
                     NULL,              // receive callback
                     on_send_complete); // send callback
    
    // Wait for handshake
    while (!lwip_ssl_is_connected("api_conn")) {
        lwip_poll();
        Sleep(10);
    }
    
    // Send request
    const char* request = "GET /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    message_sent = 0;
    
    int result = lwip_ssl_send_data("api_conn", (uint8_t*)request, strlen(request));
    
    if (result == 0) {
        // Wait for callback
        int timeout = 100; // 1 second
        while (!message_sent && timeout > 0) {
            lwip_poll();
            Sleep(10);
            timeout--;
        }
        
        if (message_sent) {
            printf("Request successfully sent!\n");
        } else {
            printf("Send timeout!\n");
        }
    }
    
    // Connection closes automatically
}
```

### Example 2: Fire-and-Forget (No Callback)

```c
void send_log_message(const char* log_msg) {
    // Simple logging - don't care about confirmation
    
    lwip_ssl_connect("log_conn", "log.example.com", 443, "log.example.com",
                     NULL,   // no handshake callback
                     NULL,   // no receive callback
                     NULL);  // no send callback
    
    // Wait for connection
    while (!lwip_ssl_is_connected("log_conn")) {
        lwip_poll();
        Sleep(10);
    }
    
    // Send and forget
    lwip_ssl_send_data("log_conn", (uint8_t*)log_msg, strlen(log_msg));
    
    // Process network events
    lwip_poll();
    
    // Connection closes automatically
    printf("Log sent (fire-and-forget)\n");
}
```

### Example 3: Multiple Sequential Requests

```c
typedef struct {
    const char* request_data;
    int completed;
} request_context_t;

request_context_t current_request;

void on_send_complete(void) {
    current_request.completed = 1;
}

void send_multiple_requests(void) {
    const char* requests[] = {
        "GET /api/user HTTP/1.1\r\n\r\n",
        "GET /api/settings HTTP/1.1\r\n\r\n",
        "GET /api/data HTTP/1.1\r\n\r\n"
    };
    
    for (int i = 0; i < 3; i++) {
        char conn_id[32];
        sprintf(conn_id, "conn_%d", i);
        
        // Connect with callback
        lwip_ssl_connect(conn_id, "api.example.com", 443, "api.example.com",
                        NULL, NULL, on_send_complete);
        
        // Wait for connection
        while (!lwip_ssl_is_connected(conn_id)) {
            lwip_poll();
            Sleep(10);
        }
        
        // Send request
        current_request.request_data = requests[i];
        current_request.completed = 0;
        
        lwip_ssl_send_data(conn_id, (uint8_t*)requests[i], strlen(requests[i]));
        
        // Wait for send to complete
        while (!current_request.completed) {
            lwip_poll();
            Sleep(10);
        }
        
        printf("Request %d sent successfully\n", i);
        
        // Connection closes automatically, proceed to next
    }
}
```

## When to Use Each Approach

| Approach | Use When | Pros | Cons |
|----------|----------|------|------|
| **With Callback** | Need confirmation | ? Asynchronous<br>? Non-blocking<br>? Clear notification | Requires callback management |
| **Without Callback** | Fire-and-forget | ? Simple<br>? No callback needed | No confirmation of queuing |
| **Return Value Check** | Synchronous operations | ? Immediate feedback<br>? Error detection | Doesn't confirm TCP send |

## Important Notes

### 1. Callback vs ACK
```c
send_complete_callback() fires when:
- SSL_write() succeeds ?
- Data is encrypted ?
- Data is queued in TCP buffer ?

BUT NOT when:
- TCP sends the packet ?
- Server receives the data ?
- TCP ACK arrives ?
```

**For TCP ACK confirmation, use persistent mode with `ack_callback`.**

### 2. Connection Lifecycle

```
Non-Persistent Mode:
???????????????
?   Connect   ?
???????????????
       ?
       ?
???????????????
?    Send     ? ? send_complete_callback fires here
???????????????
       ?
       ?
???????????????
?  Auto Close ? ? Connection closes immediately
???????????????
```

### 3. Performance Consideration

For **multiple messages**, use persistent mode instead:

```c
// ? Slow: New connection each time
for (int i = 0; i < 100; i++) {
    lwip_ssl_connect(...);
    lwip_ssl_send_data(...);  // New TLS handshake each time!
}

// ? Fast: One connection, many sends
lwip_ssl_connect_persistent(...);
for (int i = 0; i < 100; i++) {
    lwip_ssl_send_persistent(...);  // Reuse connection
}
lwip_ssl_disconnect_persistent(...);
```

## Summary

**Before (No Callback):**
- ? No way to know when message is sent
- Must rely on return value only
- No asynchronous notification

**After (With Optional Callback):**
- ? Optional `send_complete_callback`
- ? Asynchronous notification available
- ? Still works without callback (pass NULL)
- ? Consistent API with persistent mode

## Quick Reference

```c
// Minimal (no confirmation needed)
lwip_ssl_connect("c1", ip, port, host, NULL, NULL, NULL);
lwip_ssl_send_data("c1", data, len);

// With confirmation
lwip_ssl_connect("c1", ip, port, host, NULL, NULL, on_send_complete);
lwip_ssl_send_data("c1", data, len);
// ? on_send_complete() fires when queued

// Check return value
int result = lwip_ssl_send_data("c1", data, len);
if (result == 0) {
    printf("Queued successfully\n");
}
```

Choose the approach that best fits your use case!
