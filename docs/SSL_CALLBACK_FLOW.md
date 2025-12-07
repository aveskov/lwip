# SSL Wrapper Callback Flow

This document explains the two-phase callback system for persistent SSL connections, designed for high-performance message pipelining.

## Two-Phase Callback System

### Phase 1: Send Complete Callback (Immediate)
**Callback**: `ssl_send_complete_callback_t`  
**When**: Called **immediately** after `SSL_write()` succeeds  
**Purpose**: Signal that you can send the **next message** without waiting  

```c
void on_send_complete(void) {
    // SSL_write succeeded - message queued for sending
    // You can now send the NEXT message immediately!
    send_next_message();  // ? Pipeline messages for performance
}
```

### Phase 2: ACK Complete Callback (Later)
**Callback**: `ssl_send_ack_complete_callback_t`  
**When**: Called **later** when TCP ACKs the data (reliable delivery confirmed)  
**Purpose**: Confirm that a **specific message** was delivered  

```c
void on_ack_complete(const char* message_id) {
    // TCP ACK received - message definitively delivered
    // Safe to delete message from your retry queue
    mark_message_delivered(message_id);
}
```

## Performance Benefits

### Without Send Complete Callback (Slow)
```c
send_message("msg1");
// ? Must wait for ACK before sending next
wait_for_ack("msg1");  // ~50-200ms RTT delay

send_message("msg2");
wait_for_ack("msg2");  // Another RTT delay

// Result: 10 messages = 10 RTTs = 500-2000ms
```

### With Send Complete Callback (Fast - Pipelining)
```c
send_message("msg1");
// ? Send complete callback fires immediately
// ? send_message("msg2") 

send_message("msg2");
// ? Send complete callback fires immediately
// ? send_message("msg3")

// Result: 10 messages sent in <10ms
// ACK callbacks arrive later to confirm delivery
```

## Typical Usage Pattern

```c
// Connection setup
lwip_ssl_connect_persistent("conn1",
                            "192.168.1.50", 443, "example.com",
                            on_handshake,
                            NULL,  // Don't need to receive
                            on_send_complete,  // ? Phase 1: immediate
                            on_ack_complete);  // ? Phase 2: later

// Send loop
for (int i = 0; i < 100; i++) {
    char msg_id[32];
    sprintf(msg_id, "msg_%d", i);
    
    // This returns immediately after SSL_write
    lwip_ssl_send_persistent("conn1", data, len, msg_id);
    
    // on_send_complete() fires immediately
    // on_ack_complete(msg_id) fires later when ACKed
}

// Callbacks

void on_send_complete(void) {
    printf("Message queued - can send next!\n");
    // Send next message immediately (pipelining)
}

void on_ack_complete(const char* message_id) {
    printf("Message %s delivered!\n", message_id);
    // Remove from retry queue, log success, etc.
}
```

## Callback Timing Diagram

```
Time ?
0ms:   SSL_write("msg1") ? send_complete_callback()
1ms:   SSL_write("msg2") ? send_complete_callback()
2ms:   SSL_write("msg3") ? send_complete_callback()
...
50ms:  ? TCP ACK arrives ? ack_complete_callback("msg1")
51ms:  ? TCP ACK arrives ? ack_complete_callback("msg2")
52ms:  ? TCP ACK arrives ? ack_complete_callback("msg3")
```

## When to Use Each Callback

| Callback | Use For |
|----------|---------|
| `send_complete` | • Sending next message<br>• Flow control (check buffer)<br>• Performance metrics |
| `ack_complete` | • Confirming delivery<br>• Removing from retry queue<br>• Reliability tracking |

## Example: High-Performance Sender

```c
typedef struct {
    char msg_id[32];
    uint8_t data[1024];
    int len;
    int retries;
} pending_message_t;

pending_message_t retry_queue[100];
int pending_count = 0;
int in_flight = 0;

void on_send_complete(void) {
    in_flight++;
    
    // Check if we can send more
    int available = lwip_ssl_get_send_buffer_available("conn1");
    if (available > 2000 && pending_count > 0) {
        // Send next message from queue
        send_next_from_queue();
    }
}

void on_ack_complete(const char* message_id) {
    in_flight--;
    
    // Remove from retry queue
    remove_from_retry_queue(message_id);
    
    // Send more if we have buffer space
    if (pending_count > 0) {
        send_next_from_queue();
    }
}
```

## Key Points

1. **`send_complete`** = "You can send more now" (immediate)
2. **`ack_complete`** = "This message was delivered" (later)
3. **Both are optional** - but you need at least one for performance
4. **`send_complete` enables pipelining** - critical for high throughput
5. **`ack_complete` enables reliability** - critical for guaranteed delivery

## Performance Comparison

| Strategy | Throughput | Reliability |
|----------|-----------|-------------|
| No callbacks | Very slow | No confirmation |
| ACK callback only | Slow (wait for ACK) | High |
| Send complete only | **Fast (pipelining)** | Medium |
| **Both callbacks** | **Fast (pipelining)** | **High** |

## Recommended Pattern

**For maximum performance + reliability:**

```c
// Use BOTH callbacks:
// - send_complete: Queue next message immediately
// - ack_complete: Confirm delivery + handle retries

lwip_ssl_connect_persistent(id, ip, port, hostname,
                            on_handshake,
                            NULL,
                            on_send_complete,  // ? Enables pipelining
                            on_ack_complete);  // ? Enables reliability
```

This gives you:
- ? High throughput (pipelining)
- ? Reliable delivery (ACK tracking)
- ? Perfect for mission-critical high-speed messaging
