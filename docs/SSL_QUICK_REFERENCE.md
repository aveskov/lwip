# SSL Persistent Connections - Quick Reference Card

## API Functions

```c
// Create persistent SSL connection
int lwip_ssl_connect_persistent(
    const char* id,                                 // Connection ID
    const char* dest_ip,                           // Destination IP
    int port,                                       // Port (usually 443)
    const char* hostname,                          // SNI hostname
    ssl_handshake_complete_callback_t handshake_cb,// Handshake callback
    ssl_data_received_callback_t data_cb,          // Data received callback
    ssl_send_ack_complete_callback_t ack_cb);      // Message ACK callback

// Send data (fast - no handshake!)
int lwip_ssl_send_persistent(
    const char* id,                                 // Connection ID
    const uint8_t* data,                           // Data to send
    int len,                                        // Data length
    const char* message_id);                       // Message identifier

// Disconnect
void lwip_ssl_disconnect_persistent(const char* id);

// Check status
int lwip_ssl_is_connected(const char* id);
```

## Return Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Success | Continue |
| `-1` | Fatal error (connection broken) | Stop and reconnect |
| `-2` | Buffer full (temporary) | Call `lwip_poll()` and retry |

## Minimal Example

```c
// 1. Init
lwip_ssl_init_global();
lwip_create_connection("c1", "192.168.1.10", "255.255.255.0", "192.168.1.1", udp_cb, NULL);

// 2. Connect (once)
lwip_ssl_connect_persistent("c1", "10.0.0.100", 443, "example.com",
    on_handshake, on_data, on_ack);

// Wait for handshake
while (!handshake_done) { lwip_poll(); Sleep(50); }

// 3. Send many (fast!)
for (int i = 0; i < 100; i++) {
    char id[32]; sprintf(id, "msg_%d", i);
    lwip_ssl_send_persistent("c1", data, len, id);
}

// 4. Disconnect (once)
lwip_ssl_disconnect_persistent("c1");

// 5. Cleanup
lwip_ssl_cleanup_global();
```

## Error Handling Template

```c
int result = lwip_ssl_send_persistent(id, data, len, msg_id);

if (result == 0) {
    // Success
} else if (result == -2) {
    // Buffer full - RETRY
    lwip_poll();
    Sleep(50);
    result = lwip_ssl_send_persistent(id, data, len, msg_id);
} else if (result == -1) {
    // Fatal - STOP
    lwip_ssl_disconnect_persistent(id);
}
```

## Callbacks

```c
void on_handshake_complete(int success) {
    if (success) {
        // Connection ready
    } else {
        // Handshake failed
    }
}

void on_data_received(const uint8_t* data, int len) {
    // Process received data
}

void on_message_sent(const char* message_id) {
    // Message successfully sent
    printf("Message '%s' ACKed\n", message_id);
}
```

## Performance

| Operation | Non-Persistent | Persistent |
|-----------|---------------|------------|
| 1 message | 5-6 RTT | 5-6 RTT |
| 10 messages | 50-60 RTT | 10 RTT |
| 100 messages | 500-600 RTT | 55 RTT |
| **Speedup** | 1x | **~10x** |

## Common Patterns

### Pattern 1: Send-and-Forget
```c
lwip_ssl_connect_persistent("c1", ip, port, host, hndshk, data, NULL);
// wait...
for (int i = 0; i < N; i++) {
    lwip_ssl_send_persistent("c1", data, len, "msg");
}
lwip_ssl_disconnect_persistent("c1");
```

### Pattern 2: With ACK Tracking
```c
int pending = 0;
void on_ack(const char* id) { pending--; }

lwip_ssl_connect_persistent("c1", ip, port, host, hndshk, data, on_ack);
// wait...
for (int i = 0; i < N; i++) {
    lwip_ssl_send_persistent("c1", data, len, msg_id);
    pending++;
}
while (pending > 0) { lwip_poll(); Sleep(50); }  // Wait for all ACKs
lwip_ssl_disconnect_persistent("c1");
```

### Pattern 3: With Retry Logic
```c
int send_with_retry(const char* id, const uint8_t* data, int len, const char* msg_id) {
    int result = lwip_ssl_send_persistent(id, data, len, msg_id);
    if (result == -2) {
        for (int i = 0; i < 5; i++) {
            lwip_poll();
            Sleep(50);
            result = lwip_ssl_send_persistent(id, data, len, msg_id);
            if (result == 0) break;
        }
    }
    return result;
}
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Handshake fails | Check hostname, certificate, network |
| Buffer full (-2) | Increase `lwip_poll()` frequency, add retries |
| No ACK callbacks | Ensure `lwip_poll()` is called regularly |
| Connection drops | Check network stability, add reconnect logic |

## Best Practices

? Call `lwip_poll()` every 10-100ms  
? Wait for handshake before sending  
? Handle `-2` (buffer full) with retry  
? Use unique message IDs  
? Disconnect gracefully when done  
? Check return codes for all sends  

## Performance Tips

1. **Use persistent connections** for ?2 messages to same host
2. **Batch sends** without waiting for individual ACKs
3. **Call `lwip_poll()` regularly** but not excessively
4. **Reuse connections** across multiple operations
5. **Monitor buffer usage** and adjust send rate

## See Also

- `SSL_PERSISTENT_CONNECTIONS.md` - Full documentation
- `ssl_persistent_example.c` - Working examples
- `TCP_PERFORMANCE_OPTIMIZATION.md` - TCP optimization guide

---
**Version:** 1.0 | **Status:** Production Ready
