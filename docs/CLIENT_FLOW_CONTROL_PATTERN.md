# Client-Side Flow Control Pattern

## Overview

The wrapper provides two functions for high-performance TCP sending with proper flow control:

1. **`lwip_tcp_send_persistent()`** - Send data (calls callback immediately on success)
2. **`lwip_tcp_get_send_buffer_available()`** - Check buffer space before sending

## Recommended Client Pattern

### C# Example

```csharp
public class LwipTcpMessageService
{
    private const int TCP_SND_BUF = 5840;  // Match your lwipopts.h setting
    private const int FLOW_CONTROL_THRESHOLD = TCP_SND_BUF / 4;  // 25%
    
    public async Task SendMessagesAsync(List<string> messages)
    {
        foreach (var message in messages)
        {
            // Check buffer space BEFORE sending
            int available = lwip_tcp_get_send_buffer_available(connectionId);
            
            if (available < FLOW_CONTROL_THRESHOLD)
            {
                // Buffer is getting full - slow down
                _logger.LogDebug("Buffer low ({Available} bytes), waiting for drain", available);
                
                // Wait for buffer to drain
                await Task.Delay(10);  // Small delay
                
                // Check again
                available = lwip_tcp_get_send_buffer_available(connectionId);
                
                if (available < message.Length)
                {
                    _logger.LogWarning("Buffer still full after delay");
                    continue;  // Skip or retry later
                }
            }
            
            // Buffer has space - send immediately
            int result = lwip_tcp_send_persistent(
                connectionId, 
                Encoding.UTF8.GetBytes(message), 
                message.Length
            );
            
            if (result == 0)
            {
                // Success - callback will fire immediately
                await Task.Yield();  // Let callback execute
            }
            else if (result == -2)
            {
                // Buffer full (race condition) - retry
                _logger.LogDebug("Buffer filled during send, retrying");
                await Task.Delay(10);
                // Retry logic here
            }
            else
            {
                // Fatal error
                _logger.LogError("Send failed with error {Error}", result);
                break;
            }
        }
    }
}
```

### Python Example

```python
import time

TCP_SND_BUF = 5840
FLOW_CONTROL_THRESHOLD = TCP_SND_BUF // 4  # 25%

def send_messages_with_flow_control(connection_id, messages):
    for message in messages:
        # Check buffer space
        available = lwip_tcp_get_send_buffer_available(connection_id)
        
        if available < FLOW_CONTROL_THRESHOLD:
            # Buffer getting full - wait
            print(f"Buffer low ({available} bytes), waiting...")
            time.sleep(0.01)  # 10ms delay
            
            available = lwip_tcp_get_send_buffer_available(connection_id)
            if available < len(message):
                print("Buffer still full, skipping message")
                continue
        
        # Send message
        result = lwip_tcp_send_persistent(
            connection_id,
            message.encode('utf-8'),
            len(message)
        )
        
        if result == 0:
            # Success - callback fires immediately
            pass
        elif result == -2:
            # Buffer full - retry
            time.sleep(0.01)
            # Retry here
        else:
            # Fatal error
            print(f"Send failed: {result}")
            break
```

### C Example

```c
#define TCP_SND_BUF 5840
#define FLOW_CONTROL_THRESHOLD (TCP_SND_BUF / 4)

int send_messages_with_flow_control(const char* conn_id, const char** messages, int count) {
    for (int i = 0; i < count; i++) {
        const char* msg = messages[i];
        int msg_len = strlen(msg);
        
        // Check buffer space
        int available = lwip_tcp_get_send_buffer_available(conn_id);
        
        if (available < FLOW_CONTROL_THRESHOLD) {
            // Buffer getting full - wait
            printf("Buffer low (%d bytes), waiting...\n", available);
            Sleep(10);  // 10ms delay (Windows)
            
            available = lwip_tcp_get_send_buffer_available(conn_id);
            if (available < msg_len) {
                printf("Buffer still full, skipping message\n");
                continue;
            }
        }
        
        // Send message
        int result = lwip_tcp_send_persistent(conn_id, (uint8_t*)msg, msg_len);
        
        if (result == 0) {
            // Success - callback fires immediately
            // Continue to next message
        } else if (result == -2) {
            // Buffer full - retry
            Sleep(10);
            i--;  // Retry same message
        } else {
            // Fatal error
            printf("Send failed: %d\n", result);
            return -1;
        }
    }
    
    return 0;
}
```

## Performance Characteristics

### With Client-Side Flow Control

```
Scenario 1: Buffer has space (>25%)
?? Check buffer: 1460+ bytes free
?? Send message: Success
?? Callback: Fires immediately
?? Next message: Immediate (no delay)

Performance: Maximum throughput

Scenario 2: Buffer getting full (<25%)
?? Check buffer: 1000 bytes free
?? Wait 10ms for buffer to drain
?? Check buffer: 2920 bytes free
?? Send message: Success
?? Callback: Fires immediately
?? Next message: Continue

Performance: Automatic throttling
```

### Benefits

| Aspect | Benefit |
|--------|---------|
| **Throughput** | Maximum when buffer has space |
| **Reliability** | 100% - no data loss |
| **Latency** | Low - immediate callback |
| **Flow Control** | Client decides when to slow down |
| **Simplicity** | Wrapper is simple, logic in client |

## Advanced: Adaptive Threshold

For even better performance, adjust threshold based on message size:

```csharp
public class AdaptiveFlowControl
{
    private int GetThreshold(int messageSize)
    {
        // Ensure at least 2x message size in buffer
        return Math.Max(
            TCP_SND_BUF / 4,           // 25% minimum
            messageSize * 2             // 2x message size
        );
    }
    
    public async Task SendWithAdaptiveControl(string message)
    {
        int threshold = GetThreshold(message.Length);
        int available = lwip_tcp_get_send_buffer_available(connectionId);
        
        while (available < threshold)
        {
            await Task.Delay(10);
            available = lwip_tcp_get_send_buffer_available(connectionId);
        }
        
        // Now send - guaranteed to have space
        lwip_tcp_send_persistent(connectionId, bytes, length);
    }
}
```

## Comparison: Server-Side vs Client-Side Flow Control

### Server-Side (Previous Approach)

```c
// Wrapper decides when to call callback
if (remaining > TCP_SND_BUF / 4) {
    callback();  // Call now
} else {
    // Wait for on_tcp_sent_persistent()
}
```

**Pros**:
- Client doesn't need to check buffer
- Automatic flow control

**Cons**:
- Wrapper more complex
- Client has less control
- Can't adjust threshold per message

### Client-Side (Current Approach)

```c
// Wrapper always calls callback immediately
callback();  // Always call after successful write

// Client checks buffer before sending
if (lwip_tcp_get_send_buffer_available(id) < threshold) {
    wait();
}
```

**Pros**:
- Wrapper is simple
- Client has full control
- Can adjust threshold dynamically
- Better for high-performance scenarios

**Cons**:
- Client must implement flow control
- Slightly more code on client side

## Recommended Thresholds

| Use Case | Threshold | Rationale |
|----------|-----------|-----------|
| **Small messages (<500 bytes)** | 25% (1460 bytes) | Allows ~3 messages in flight |
| **Medium messages (500-1000 bytes)** | 33% (1946 bytes) | Allows ~2 messages in flight |
| **Large messages (>1000 bytes)** | 50% (2920 bytes) | Allows 1 full message in flight |
| **Bulk transfer** | 75% (4380 bytes) | Maximum throughput |

## Example: High-Performance Bulk Send

```csharp
public async Task BulkSendAsync(List<string> messages)
{
    var sendTasks = new List<Task>();
    
    foreach (var message in messages)
    {
        // Wait until buffer has space
        while (lwip_tcp_get_send_buffer_available(connId) < TCP_SND_BUF / 4)
        {
            await Task.Delay(1);  // Very short delay
        }
        
        // Send and don't wait for callback
        int result = lwip_tcp_send_persistent(connId, bytes, length);
        
        if (result == 0)
        {
            // Continue immediately to next message
            // Callback will fire asynchronously
        }
    }
    
    // All messages queued successfully
}
```

## Summary

**Key Principle**: Check buffer **before** sending, not **after**.

```
? GOOD: Check ? Send ? Callback (immediate)
? BAD:  Send ? Check ? Wait ? Callback
```

This approach gives you:
- **Maximum throughput** when buffer has space
- **Automatic throttling** when buffer fills
- **100% reliability** - no data loss
- **Client control** - you decide the flow control policy
