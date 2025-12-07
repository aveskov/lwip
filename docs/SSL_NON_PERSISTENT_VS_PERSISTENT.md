# SSL Callback Comparison: Non-Persistent vs Persistent

## Question: How does `lwip_ssl_connect` handle complete callbacks?

## Answer: Non-Persistent Mode Does NOT Have Send Complete Callback

### Current Design:

| Mode | Function | Send Complete Callback? | Reason |
|------|----------|------------------------|--------|
| **Non-Persistent** | `lwip_ssl_connect()` | ? **NO** | Connection closes immediately after single send |
| **Persistent** | `lwip_ssl_connect_persistent()` | ? **YES** | Connection stays open for multiple sends |

## Non-Persistent Mode (`lwip_ssl_connect`)

### Function Signature:
```c
int lwip_ssl_connect(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,
                     ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb);
// ? NO send_complete_cb parameter
```

### Why No Send Complete Callback?

**Because the connection lifecycle is:**
1. Connect
2. Send **ONE** message with `lwip_ssl_send_data()`
3. Connection closes automatically

**There's nothing to "pipeline"** - you only send one message and the connection ends.

### Usage Example:
```c
// Non-persistent: one message per connection
lwip_ssl_connect("conn1", "192.168.1.50", 443, "example.com",
                 on_handshake,
                 NULL);  // No send callback needed

// Send one message
lwip_ssl_send_data("conn1", data, len);
// ? Connection closes after this

// To send another message, must reconnect
lwip_ssl_connect("conn2", "192.168.1.50", 443, "example.com", ...);
lwip_ssl_send_data("conn2", data2, len2);
```

### When to Use Non-Persistent:
- ? Sending single messages (e.g., one-off API calls)
- ? Simplicity - no callback management needed
- ? Low message volume
- ? **NOT** for high-performance or multiple messages

---

## Persistent Mode (`lwip_ssl_connect_persistent`)

### Function Signature:
```c
int lwip_ssl_connect_persistent(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,
                     ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_complete_callback_t send_complete_cb,  // ? HAS THIS
                     ssl_send_ack_complete_callback_t ack_cb);
```

### Why Has Send Complete Callback?

**Because the connection stays open:**
1. Connect **once**
2. Send **many** messages with `lwip_ssl_send_persistent()`
3. Disconnect when done

**Send complete callback enables pipelining** - you need to know when to send the next message.

### Usage Example:
```c
// Persistent: one connection, many messages
lwip_ssl_connect_persistent("conn1", "192.168.1.50", 443, "example.com",
                            on_handshake,
                            NULL,
                            on_send_complete,  // ? Called immediately
                            on_ack_complete);  // ? Called later

// Send many messages on same connection
for (int i = 0; i < 100; i++) {
    char msg_id[32];
    sprintf(msg_id, "msg_%d", i);
    lwip_ssl_send_persistent("conn1", data, len, msg_id);
    // on_send_complete() fires immediately - can send next!
    // on_ack_complete(msg_id) fires 50-200ms later when ACKed
}

// Disconnect when done
lwip_ssl_disconnect_persistent("conn1");

void on_send_complete(void) {
    printf("Message queued - send next!\n");
    // Send next message immediately (pipelining)
}

void on_ack_complete(const char* msg_id) {
    printf("Message %s delivered!\n", msg_id);
}
```

### When to Use Persistent:
- ? Sending multiple messages
- ? High performance needed (pipelining)
- ? Need ACK confirmation for reliability
- ? Avoid TLS handshake overhead (3-4 RTTs per connection)

---

## Side-by-Side Comparison

### Non-Persistent (Simple)
```c
// Setup - no callbacks needed
lwip_ssl_connect("c1", ip, port, host, on_handshake, NULL);

// Send ONE message
lwip_ssl_send_data("c1", data, len);
// ? Returns when queued
// ? Connection closes automatically

// Need new connection for next message
```

**Pros:**
- Simple API
- No callback management
- Good for one-off messages

**Cons:**
- Slow (new connection per message)
- 3-4 RTT handshake overhead each time
- Can't pipeline

### Persistent (High-Performance)
```c
// Setup - provide callbacks
lwip_ssl_connect_persistent("c1", ip, port, host,
                            on_handshake, NULL,
                            on_send_complete,  // immediate
                            on_ack_complete);  // later

// Send MANY messages
lwip_ssl_send_persistent("c1", data1, len1, "msg1");
// on_send_complete() ? send next immediately!
lwip_ssl_send_persistent("c1", data2, len2, "msg2");
// on_send_complete() ? send next immediately!
// ... (continue sending)

// Later: on_ack_complete("msg1") 
// Later: on_ack_complete("msg2")

// Disconnect when done
lwip_ssl_disconnect_persistent("c1");
```

**Pros:**
- Fast (reuse connection)
- Pipelining enabled
- ACK tracking for reliability
- One handshake for many messages

**Cons:**
- More complex API
- Must manage callbacks
- Need message ID tracking

---

## Performance Comparison

### Send 100 Messages

#### Non-Persistent
```
Connect #1 (handshake: 200ms) ? Send ? Close
Connect #2 (handshake: 200ms) ? Send ? Close
...
Connect #100 (handshake: 200ms) ? Send ? Close

Total: 100 connections × 200ms = 20+ seconds!
```

#### Persistent
```
Connect once (handshake: 200ms)
Send msg1 ? on_send_complete() ? Send msg2 ? ...
Send all 100 messages: <100ms

Total: 200ms handshake + 100ms sends = ~300ms!
```

**Speedup: 70x faster!**

---

## Summary

| Feature | Non-Persistent | Persistent |
|---------|---------------|-----------|
| **Send Complete Callback** | ? No | ? Yes |
| **ACK Callback** | ? No | ? Yes |
| **Connection Reuse** | ? No | ? Yes |
| **Pipelining** | ? No | ? Yes |
| **Use Case** | Single messages | Multiple messages |
| **Performance** | Slow | Fast |
| **Complexity** | Simple | Medium |

## Recommendation

- **Use Non-Persistent** (`lwip_ssl_connect`) if:
  - You send occasional single messages
  - Simplicity > performance
  - Example: Periodic health checks, one-off API calls

- **Use Persistent** (`lwip_ssl_connect_persistent`) if:
  - You send multiple messages in sequence
  - Performance matters
  - You need delivery confirmation
  - Example: Streaming data, batch operations, real-time messaging

---

## Direct Answer to Your Question

**Q: "If I also use `lwip_ssl_connect` how complete callback will be called?"**

**A:** The complete callback **will NOT be called** in non-persistent mode because:

1. `lwip_ssl_connect()` doesn't accept a `send_complete_callback` parameter
2. The connection closes immediately after `lwip_ssl_send_data()`
3. There's no need for a callback because there's only one send operation
4. The function returns synchronously when data is queued

If you need callbacks for multiple sends, use `lwip_ssl_connect_persistent()` instead.
