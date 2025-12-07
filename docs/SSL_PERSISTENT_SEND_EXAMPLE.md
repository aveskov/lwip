# Persistent SSL Connection - Multiple Messages Example

This document demonstrates how to send multiple messages over a persistent SSL connection with proper flow control, error handling, and ACK tracking.

## Complete C Example

```c
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "lwip_wrapper.h"
#include "lwip_wrapper_ssl.h"

// Connection state tracking
typedef struct {
    int handshake_completed;
    int total_messages_sent;
    int total_messages_acked;
    int send_errors;
    int is_connected;
} ssl_session_state_t;

static ssl_session_state_t session_state = {0};

// Callback: SSL handshake completed
void on_ssl_handshake_complete(int success) {
    if (success) {
        printf("? SSL handshake successful!\n");
        session_state.handshake_completed = 1;
        session_state.is_connected = 1;
    } else {
        printf("? SSL handshake failed!\n");
        session_state.is_connected = 0;
    }
}

// Callback: Data received from server (e.g., HTTP response)
void on_ssl_data_received(const uint8_t* data, int len) {
    printf("? Received %d bytes from server:\n", len);
    printf("%.*s\n", len, data);
}

// Callback: Message queued for sending (immediate feedback)
void on_ssl_send_complete(void) {
    session_state.total_messages_sent++;
    printf("? Message #%d queued for sending\n", session_state.total_messages_sent);
}

// Callback: Message ACKed by remote peer (delivery confirmation)
void on_ssl_ack_complete(const char* message_id) {
    session_state.total_messages_acked++;
    printf("? Message ACKed: %s (Total ACKed: %d)\n", 
           message_id, session_state.total_messages_acked);
}

// Helper: Wait for handshake to complete
int wait_for_handshake(int timeout_ms) {
    int elapsed = 0;
    int poll_interval = 50; // ms
    
    printf("Waiting for SSL handshake...\n");
    
    while (!session_state.handshake_completed && elapsed < timeout_ms) {
        lwip_poll(); // Process LwIP timers and callbacks
        Sleep(poll_interval);
        elapsed += poll_interval;
    }
    
    if (!session_state.handshake_completed) {
        printf("? Handshake timeout after %d ms\n", timeout_ms);
        return -1;
    }
    
    printf("? Handshake completed in %d ms\n", elapsed);
    return 0;
}

// Helper: Send message with retry logic
int send_ssl_message_with_retry(const char* conn_id, const uint8_t* data, 
                                int len, const char* message_id, int max_retries) {
    int retries = 0;
    int result;
    
    while (retries <= max_retries) {
        // Check buffer availability first
        int available = lwip_ssl_get_send_buffer_available(conn_id);
        if (available < 0) {
            printf("? Connection closed or invalid\n");
            return -1;
        }
        
        printf("  Buffer available: %d bytes (need: %d)\n", available, len);
        
        // Try to send
        result = lwip_ssl_send_persistent(conn_id, data, len, message_id);
        
        if (result == 0) {
            // Success!
            return 0;
        } else if (result == -2) {
            // Buffer full - retry after polling
            printf("  ? Buffer full, retry #%d/%d...\n", retries + 1, max_retries);
            lwip_poll(); // Process ACKs to free buffer space
            Sleep(100);  // Wait a bit
            retries++;
        } else {
            // Fatal error (-1)
            printf("? Fatal send error: %d\n", result);
            session_state.send_errors++;
            return -1;
        }
    }
    
    printf("? Send failed after %d retries (buffer full)\n", max_retries);
    return -2;
}

// Main function: Send multiple HTTPS requests
int main(void) {
    const char* conn_id = "ssl_conn_1";
    const char* server_ip = "93.184.216.34"; // example.com IP
    int server_port = 443;
    const char* hostname = "example.com";
    int result;
    
    printf("=== Persistent SSL Connection Example ===\n\n");
    
    // Step 1: Initialize LwIP stack
    printf("1. Initializing LwIP stack...\n");
    lwip_init_stack_global();
    lwip_ssl_init_global();
    printf("? LwIP initialized\n\n");
    
    // Step 2: Create base connection
    printf("2. Creating base connection...\n");
    result = lwip_create_connection(
        conn_id,
        "10.0.0.2",      // Local source IP
        "255.255.255.0", // Netmask
        "10.0.0.1",      // Gateway
        NULL,            // UDP callback (not needed for SSL)
        NULL             // send_complete_callback (use SSL-specific callback instead)
    );
    
    if (result != 0) {
        printf("? Failed to create connection\n");
        return -1;
    }
    printf("? Base connection created\n\n");
    
    // Step 3: Establish persistent SSL connection
    printf("3. Connecting to %s:%d (SSL/TLS)...\n", server_ip, server_port);
    result = lwip_ssl_connect_persistent(
        conn_id,
        server_ip,
        server_port,
        hostname,
        on_ssl_handshake_complete,    // Handshake callback
        on_ssl_data_received,          // Data received callback
        on_ssl_send_complete,          // Immediate send callback
        on_ssl_ack_complete            // ACK confirmation callback
    );
    
    if (result != 0) {
        printf("? Failed to initiate SSL connection\n");
        lwip_close_connection(conn_id);
        return -1;
    }
    printf("? SSL connection initiated\n\n");
    
    // Step 4: Wait for SSL handshake to complete
    printf("4. Completing SSL handshake...\n");
    if (wait_for_handshake(10000) != 0) {
        printf("? Handshake failed\n");
        lwip_ssl_disconnect_persistent(conn_id);
        lwip_close_connection(conn_id);
        return -1;
    }
    printf("\n");
    
    // Step 5: Send multiple HTTPS requests over the same connection
    printf("5. Sending multiple HTTPS requests...\n\n");
    
    const char* http_requests[] = {
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: lwip-ssl-client/1.0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        
        "GET /page1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: lwip-ssl-client/1.0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        
        "GET /page2 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: lwip-ssl-client/1.0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        
        "GET /page3 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: lwip-ssl-client/1.0\r\n"
        "Connection: close\r\n"  // Close after last request
        "\r\n"
    };
    
    int num_requests = sizeof(http_requests) / sizeof(http_requests[0]);
    
    for (int i = 0; i < num_requests; i++) {
        char message_id[32];
        snprintf(message_id, sizeof(message_id), "REQUEST_%d", i + 1);
        
        printf("--- Sending Request #%d (ID: %s) ---\n", i + 1, message_id);
        
        // Check if still connected
        if (!lwip_ssl_is_connected(conn_id)) {
            printf("? Connection lost!\n");
            session_state.is_connected = 0;
            break;
        }
        
        // Send with automatic retry on buffer full
        result = send_ssl_message_with_retry(
            conn_id,
            (const uint8_t*)http_requests[i],
            strlen(http_requests[i]),
            message_id,
            5  // Max 5 retries
        );
        
        if (result != 0) {
            printf("? Failed to send request #%d\n", i + 1);
            break;
        }
        
        // Monitor pending ACKs
        int pending_acks = lwip_ssl_get_pending_ack_count(conn_id);
        printf("  Pending ACKs: %d\n", pending_acks);
        
        // Poll to process responses and ACKs
        printf("  Processing responses...\n");
        for (int j = 0; j < 20; j++) {  // Poll for 2 seconds
            lwip_poll();
            Sleep(100);
        }
        
        printf("\n");
    }
    
    // Step 6: Wait for all ACKs
    printf("6. Waiting for all ACKs to complete...\n");
    int wait_cycles = 0;
    int max_wait_cycles = 100;  // 10 seconds max
    
    while (wait_cycles < max_wait_cycles) {
        int pending = lwip_ssl_get_pending_ack_count(conn_id);
        if (pending <= 0) {
            printf("? All messages ACKed!\n");
            break;
        }
        
        printf("  Pending ACKs: %d\r", pending);
        lwip_poll();
        Sleep(100);
        wait_cycles++;
    }
    
    if (wait_cycles >= max_wait_cycles) {
        printf("\n? Timeout waiting for ACKs\n");
    }
    printf("\n");
    
    // Step 7: Close SSL connection gracefully
    printf("7. Closing SSL connection...\n");
    lwip_ssl_disconnect_persistent(conn_id);
    
    // Give time for graceful shutdown
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(100);
    }
    printf("? SSL connection closed\n\n");
    
    // Step 8: Close base connection
    printf("8. Cleaning up...\n");
    lwip_close_connection(conn_id);
    lwip_ssl_cleanup_global();
    printf("? Cleanup complete\n\n");
    
    // Step 9: Print statistics
    printf("=== Session Statistics ===\n");
    printf("Messages sent:       %d\n", session_state.total_messages_sent);
    printf("Messages ACKed:      %d\n", session_state.total_messages_acked);
    printf("Send errors:         %d\n", session_state.send_errors);
    printf("Final status:        %s\n", 
           session_state.is_connected ? "Connected" : "Disconnected");
    
    if (session_state.total_messages_sent == session_state.total_messages_acked) {
        printf("\n? All messages delivered successfully!\n");
        return 0;
    } else {
        printf("\n? Some messages not ACKed (%d pending)\n",
               session_state.total_messages_sent - session_state.total_messages_acked);
        return 1;
    }
}
```

## Key Implementation Details

### 1. Connection Setup Flow

```
lwip_init_stack_global()
    ?
lwip_ssl_init_global()
    ?
lwip_create_connection()  // Base connection
    ?
lwip_ssl_connect_persistent()  // SSL layer
    ?
wait_for_handshake()  // Poll until handshake completes
    ?
Ready to send messages!
```

### 2. Message Sending Pattern

```c
// Check connection status
if (!lwip_ssl_is_connected(conn_id)) {
    // Handle disconnection
}

// Check buffer availability
int available = lwip_ssl_get_send_buffer_available(conn_id);
if (available < message_length) {
    // Buffer full - need to wait
    lwip_poll();  // Process ACKs
    Sleep(100);
    // Retry
}

// Send message with unique ID
result = lwip_ssl_send_persistent(conn_id, data, len, "MSG_001");
if (result == 0) {
    // Success - message queued
} else if (result == -2) {
    // Buffer full - retry after lwip_poll()
} else {
    // Fatal error - connection broken
}
```

### 3. Callback Flow

```
Message Send Flow:
??????????????????

Your Code:
  lwip_ssl_send_persistent(id, data, len, "MSG_001")
      ?
  SSL_write() encrypts data
      ?
  ? on_ssl_send_complete()  ? IMMEDIATE: Message queued
      ?
  tcp_write() sends encrypted data
      ?
  [Time passes - data transmitted over network]
      ?
  TCP ACK received from remote
      ?
  ? on_ssl_ack_complete("MSG_001")  ? LATER: Delivery confirmed
```

### 4. Error Handling Strategy

| Return Code | Meaning | Action |
|------------|---------|--------|
| `0` | Success | Continue sending |
| `-2` | Buffer full | Retry after `lwip_poll()` + `Sleep()` |
| `-1` | Fatal error | Stop sending, close connection |

### 5. Flow Control Pattern

```c
int send_with_flow_control(const char* id, const uint8_t* data, int len) {
    int max_retries = 5;
    int retry_count = 0;
    
    while (retry_count < max_retries) {
        int result = lwip_ssl_send_persistent(id, data, len, "MSG_ID");
        
        if (result == 0) {
            return 0;  // Success
        }
        
        if (result == -2) {
            // Buffer full - retry with backoff
            lwip_poll();
            Sleep(100 * (retry_count + 1));  // Exponential backoff
            retry_count++;
            continue;
        }
        
        // Fatal error
        return -1;
    }
    
    return -2;  // Max retries exceeded
}
```

## Best Practices

### 1. Always Call `lwip_poll()` Regularly

```c
// In a separate timer thread or main loop:
while (connection_active) {
    lwip_poll();  // Process timers, ACKs, retransmissions
    Sleep(50);    // Poll every 50ms
}
```

### 2. Monitor Buffer Space

```c
// Before sending large messages:
int available = lwip_ssl_get_send_buffer_available(conn_id);
if (available < message_size) {
    // Wait for buffer to drain
    while (lwip_ssl_get_send_buffer_available(conn_id) < message_size) {
        lwip_poll();
        Sleep(50);
    }
}
```

### 3. Track Message IDs

```c
// Use sequential or UUID-based message IDs
char msg_id[64];
snprintf(msg_id, sizeof(msg_id), "MSG_%d_%lld", 
         sequence_number, GetTickCount64());

lwip_ssl_send_persistent(conn_id, data, len, msg_id);
```

### 4. Handle Connection Loss

```c
// Check connection before each send
if (!lwip_ssl_is_connected(conn_id)) {
    // Reconnect or fail gracefully
    if (reconnect_ssl_connection(conn_id) != 0) {
        return -1;
    }
}
```

### 5. Graceful Shutdown

```c
// 1. Stop sending new messages
sending_active = 0;

// 2. Wait for pending ACKs
while (lwip_ssl_get_pending_ack_count(conn_id) > 0) {
    lwip_poll();
    Sleep(100);
}

// 3. Close SSL connection
lwip_ssl_disconnect_persistent(conn_id);

// 4. Poll to complete shutdown
for (int i = 0; i < 20; i++) {
    lwip_poll();
    Sleep(50);
}

// 5. Close base connection
lwip_close_connection(conn_id);
```

## Performance Tips

### 1. Reduce Latency
- Keep Nagle's algorithm disabled (default)
- Send messages immediately when buffer available
- Use persistent connections to avoid handshake overhead

### 2. Increase Throughput
- Pipeline multiple messages without waiting for ACKs
- Monitor buffer space and send continuously
- Use larger messages when possible

### 3. Optimal Buffer Management
```c
// High-throughput sending pattern:
const int TARGET_PENDING_ACKS = 5;  // Keep pipeline full

while (has_more_messages()) {
    int pending = lwip_ssl_get_pending_ack_count(conn_id);
    
    if (pending < TARGET_PENDING_ACKS) {
        // Pipeline not full - send more
        send_next_message();
    } else {
        // Pipeline full - wait for ACKs
        lwip_poll();
        Sleep(10);
    }
}
```

## Common Pitfalls to Avoid

### ? DON'T: Send without checking return value
```c
// BAD - ignores errors
lwip_ssl_send_persistent(id, data, len, "MSG");
```

### ? DO: Check and handle return values
```c
// GOOD - handles all cases
int result = lwip_ssl_send_persistent(id, data, len, "MSG");
if (result == -2) {
    // Retry logic
} else if (result == -1) {
    // Fatal error handling
}
```

### ? DON'T: Forget to call `lwip_poll()`
```c
// BAD - timers never fire, buffers never drain
while (sending) {
    lwip_ssl_send_persistent(...);
    Sleep(1000);  // No lwip_poll()!
}
```

### ? DO: Call `lwip_poll()` regularly
```c
// GOOD - maintains TCP connection health
while (sending) {
    lwip_ssl_send_persistent(...);
    lwip_poll();  // Essential!
    Sleep(50);
}
```

### ? DON'T: Retry on fatal errors
```c
// BAD - infinite loop on broken connection
do {
    result = lwip_ssl_send_persistent(...);
} while (result != 0);  // Retries even on -1!
```

### ? DO: Distinguish retry vs fatal errors
```c
// GOOD - stops on fatal error
do {
    result = lwip_ssl_send_persistent(...);
    if (result == -1) break;  // Fatal - stop
    if (result == -2) {
        lwip_poll();
        Sleep(100);
    }
} while (result == -2);  // Only retry on buffer full
```

## Conclusion

Persistent SSL connections allow high-performance message sending with:
- ? Reusable connections (no handshake overhead)
- ? Immediate send feedback (`ssl_send_complete_callback`)
- ? Delivery confirmation (`ssl_ack_complete_callback`)
- ? Flow control (buffer checking and retry logic)
- ? Message tracking (unique message IDs)

Always remember to:
1. Call `lwip_poll()` regularly
2. Check return values
3. Retry on `-2` (buffer full)
4. Stop on `-1` (fatal error)
5. Wait for handshake before sending
6. Monitor pending ACKs for graceful shutdown
