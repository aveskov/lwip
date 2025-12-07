# API Simplification - Migration Guide

## Overview

The API has been simplified to make message ID tracking the **default behavior** for persistent TCP connections.

## What Changed

### Before (Complex)

```c
// Step 1: Connect
int lwip_tcp_connect_persistent(const char* id, const char* dest_ip, int port);

// Step 2: Set ACK callback (separate call)
void lwip_set_ack_callback(const char* id, send_ack_complete_callback_t ack_cb);

// Step 3: Choose send method
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len);  // No tracking
int lwip_tcp_send_persistent_with_id(const char* id, const uint8_t* data, int len, const char* message_id);  // With tracking
```

### After (Simplified)

```c
// Step 1: Connect with ACK callback (one call)
int lwip_tcp_connect_persistent(const char* id, const char* dest_ip, int port, send_ack_complete_callback_t ack_cb);

// Step 2: Send with message ID (mandatory)
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id);
```

## Benefits

| Aspect | Before | After |
|--------|--------|-------|
| **API calls** | 3 steps | 2 steps |
| **Complexity** | 2 send functions | 1 send function |
| **Message tracking** | Optional | Always enabled |
| **Configuration** | Separate calls | Combined in connect |
| **Clarity** | Confusing | Clear |

## C# Migration

### Before

```csharp
// Establish connection
LwipNative.lwip_tcp_connect_persistent(ConnectionId, ipAddress, port);

// Set ACK callback separately
LwipNative.lwip_set_ack_callback(ConnectionId, OnMessageAcknowledged);

// Send with or without ID
LwipNative.lwip_tcp_send_persistent(ConnectionId, data, len);  // No tracking
LwipNative.lwip_tcp_send_persistent_with_id(ConnectionId, data, len, messageId);  // With tracking
```

### After

```csharp
// Establish connection with ACK callback in one call
LwipNative.lwip_tcp_connect_persistent(
    ConnectionId, 
    ipAddress, 
    port,
    OnMessageAcknowledged);  // ? Callback set here!

// Send always includes message ID (mandatory)
LwipNative.lwip_tcp_send_persistent(
    ConnectionId, 
    data, 
    len, 
    messageId);  // ? message_id is mandatory
```

## API Changes Summary

### Removed Functions

```c
? void lwip_set_ack_callback(const char* id, send_ack_complete_callback_t ack_cb);
   // Merged into lwip_tcp_connect_persistent()

? int lwip_tcp_send_persistent_with_id(const char* id, const uint8_t* data, int len, const char* message_id);
   // Renamed to lwip_tcp_send_persistent() - it's now the default!
```

### Modified Functions

```c
// Old signature
int lwip_tcp_connect_persistent(const char* id, const char* dest_ip, int port);

// ? New signature
int lwip_tcp_connect_persistent(
    const char* id, 
    const char* dest_ip, 
    int port, 
    send_ack_complete_callback_t ack_cb);  // ACK callback added

// Old signature (no message ID)
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len);

// ? New signature (message ID mandatory)
int lwip_tcp_send_persistent(
    const char* id, 
    const uint8_t* data, 
    int len, 
    const char* message_id);  // message_id is mandatory
```

## Step-by-Step Migration

### Step 1: Update Connection Establishment

**Before:**
```csharp
private async Task EstablishTcpConnectionIfNeeded(string hostName, int port)
{
    var address = GetIpAddress(hostName);
    
    LwipNative.lwip_tcp_connect_persistent(ConnectionId, address.ToString(), port);
    
    // Separate call to set callback
    LwipNative.lwip_set_ack_callback(ConnectionId, OnMessageAcknowledged);
    
    // Wait for connection
    await WaitForConnection();
}
```

**After:**
```csharp
private async Task EstablishTcpConnectionIfNeeded(string hostName, int port)
{
    var address = GetIpAddress(hostName);
    
    // ? One call - callback included
    LwipNative.lwip_tcp_connect_persistent(
        ConnectionId, 
        address.ToString(), 
        port,
        OnMessageAcknowledged);
    
    // Wait for connection
    await WaitForConnection();
}
```

### Step 2: Update Send Calls

**Before:**
```csharp
// Option 1: Send without tracking (removed)
LwipNative.lwip_tcp_send_persistent(ConnectionId, messageBytes, messageBytes.Length);

// Option 2: Send with tracking
var messageId = GenerateMessageId();
LwipNative.lwip_tcp_send_persistent_with_id(
    ConnectionId, 
    messageBytes, 
    messageBytes.Length,
    messageId);
```

**After:**
```csharp
// ? Only one option - message ID is mandatory
var messageId = GenerateMessageId();
LwipNative.lwip_tcp_send_persistent(
    ConnectionId, 
    messageBytes, 
    messageBytes.Length,
    messageId);  // message_id is required
```

### Step 3: Update P/Invoke Declarations

**Before:**
```csharp
[DllImport("lwip_wrapper")]
public static extern int lwip_tcp_connect_persistent(
    string id, string destIp, int port);

[DllImport("lwip_wrapper")]
public static extern void lwip_set_ack_callback(
    string id, SendAckCompleteCallback ackCallback);

[DllImport("lwip_wrapper")]
public static extern int lwip_tcp_send_persistent(
    string id, byte[] data, int len);

[DllImport("lwip_wrapper")]
public static extern int lwip_tcp_send_persistent_with_id(
    string id, byte[] data, int len, string messageId);
```

**After:**
```csharp
// ? Simplified - only 2 functions
[DllImport("lwip_wrapper", CallingConvention = CallingConvention.Cdecl)]
public static extern int lwip_tcp_connect_persistent(
    [MarshalAs(UnmanagedType.LPStr)] string id,
    [MarshalAs(UnmanagedType.LPStr)] string destIp,
    int port,
    [MarshalAs(UnmanagedType.FunctionPtr)] SendAckCompleteCallback ackCallback);

[DllImport("lwip_wrapper", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
public static extern int lwip_tcp_send_persistent(
    [MarshalAs(UnmanagedType.LPStr)] string id,
    byte[] data,
    int len,
    [MarshalAs(UnmanagedType.LPStr)] string messageId);
```

## Complete Example

### Before (Old API)

```csharp
public class OldLwipService
{
    private string _connectionId;
    
    public async Task SendAsync(string host, int port, string message)
    {
        // Step 1: Connect
        LwipNative.lwip_tcp_connect_persistent(_connectionId, host, port);
        
        // Step 2: Set callback
        LwipNative.lwip_set_ack_callback(_connectionId, OnAck);
        
        // Step 3: Wait for connection
        await WaitForConnection();
        
        // Step 4: Send (choose method)
        var messageBytes = Encoding.UTF8.GetBytes(message);
        
        // Without tracking
        LwipNative.lwip_tcp_send_persistent(_connectionId, messageBytes, messageBytes.Length);
        
        // OR with tracking
        var messageId = Guid.NewGuid().ToString();
        LwipNative.lwip_tcp_send_persistent_with_id(
            _connectionId, messageBytes, messageBytes.Length, messageId);
    }
    
    private void OnAck(string messageId)
    {
        Console.WriteLine($"ACK: {messageId}");
    }
}
```

### After (New API)

```csharp
public class NewLwipService
{
    private string _connectionId;
    
    public async Task SendAsync(string host, int port, string message)
    {
        // Step 1: Connect with callback (one call!)
        LwipNative.lwip_tcp_connect_persistent(
            _connectionId, 
            host, 
            port,
            OnAck);  // ? Callback included
        
        // Step 2: Wait for connection
        await WaitForConnection();
        
        // Step 3: Send with message ID (mandatory)
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var messageId = GenerateMessageId();
        
        LwipNative.lwip_tcp_send_persistent(
            _connectionId, 
            messageBytes, 
            messageBytes.Length, 
            messageId);  // ? message_id required
    }
    
    private void OnAck(string messageId)
    {
        Console.WriteLine($"ACK: {messageId}");
    }
    
    private string GenerateMessageId()
    {
        return $"msg_{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}";
    }
}
```

## Breaking Changes Checklist

- [ ] Update `lwip_tcp_connect_persistent()` calls to include ACK callback parameter
- [ ] Remove all `lwip_set_ack_callback()` calls (merged into connect)
- [ ] Rename `lwip_tcp_send_persistent_with_id()` to `lwip_tcp_send_persistent()`
- [ ] Add `message_id` parameter to all `lwip_tcp_send_persistent()` calls
- [ ] Update P/Invoke declarations
- [ ] Implement message ID generation strategy
- [ ] Test ACK callback handling

## Migration Time Estimate

| Codebase Size | Estimated Time |
|---------------|---------------|
| Small (1-2 files) | 10-15 minutes |
| Medium (5-10 files) | 30-45 minutes |
| Large (20+ files) | 1-2 hours |

## Compatibility

### ? Not Backward Compatible

The API has **breaking changes**. Old code will **not compile** without updates.

### ? Easy Migration

All changes are **mechanical** - simple find and replace:

1. Find: `lwip_tcp_connect_persistent(id, ip, port)`
   Replace: `lwip_tcp_connect_persistent(id, ip, port, OnMessageAck)`

2. Find: `lwip_set_ack_callback(id, callback)`
   Replace: (delete - now in connect)

3. Find: `lwip_tcp_send_persistent_with_id(`
   Replace: `lwip_tcp_send_persistent(`

4. Find: `lwip_tcp_send_persistent(id, data, len)`
   Replace: `lwip_tcp_send_persistent(id, data, len, GenerateMessageId())`

## Why This Change?

### Problems with Old API

1. **Confusing** - Why two send functions?
2. **Error-prone** - Easy to forget `lwip_set_ack_callback()`
3. **Verbose** - Three separate calls to set up
4. **Inconsistent** - Some sends tracked, some not

### Benefits of New API

1. **Simpler** - One way to do things
2. **Safer** - Can't forget to set callback
3. **Clearer** - Message tracking is always enabled
4. **Better** - Encourages best practices

## FAQ

### Q: What if I don't need ACK tracking?

**A:** Pass `NULL` for the callback:

```c
lwip_tcp_connect_persistent(id, ip, port, NULL);  // No ACK tracking
```

But you still must provide a `message_id` when sending (it will be ignored).

### Q: Can I change the ACK callback after connecting?

**A:** No. The callback is set once during connection. If you need different behavior, disconnect and reconnect.

### Q: What if I send the same message_id twice?

**A:** Don't do this! Each message needs a **unique ID**. Use timestamps, GUIDs, or sequential numbers.

### Q: Do I need to track message IDs in my code?

**A:** Yes! The ACK callback gives you the `message_id`, so you need to maintain a mapping:

```csharp
private ConcurrentDictionary<string, MessageInfo> _pending = new();

// When sending
_pending[messageId] = new MessageInfo { SentTime = DateTime.UtcNow };

// In callback
private void OnAck(string messageId)
{
    if (_pending.TryRemove(messageId, out var info))
    {
        var latency = DateTime.UtcNow - info.SentTime;
        _logger.LogInfo("Message {Id} ACKed in {Ms}ms", messageId, latency.TotalMilliseconds);
    }
}
```

## Summary

| Change | Old | New |
|--------|-----|-----|
| **Connect** | 2 calls (connect + set_callback) | 1 call (connect with callback) |
| **Send** | 2 functions (with/without ID) | 1 function (ID mandatory) |
| **Complexity** | Higher | Lower |
| **Safety** | Can forget callback | Callback guaranteed |
| **Tracking** | Optional | Always enabled |

**Migration effort**: Low (mechanical changes)

**Benefit**: High (simpler, clearer API)

---

**Recommendation**: ? **Migrate immediately** - the new API is much better!
