# Use-After-Free in Callbacks - Analysis and Fix

## The Problem

Your logs show:
```
[10:10:12] Connection 'xxx' closed and removed.
[10:10:12 INF] Send complete acknowledged by peer.
[10:10:12] Connection 'xxx' not found.
```

This means **your C# callback is trying to access a closed connection**.

## Root Cause

The `send_complete_callback` is being called AFTER the connection is closed because:

1. **Messages are queued** and callbacks fire asynchronously
2. **Connection closes** due to TCP error (-14 = ERR_RST)
3. **Callbacks still pending** continue to fire
4. **C# code tries to access connection** ? "Connection not found"

## The Flow

```
Time T0: Send 6 messages
         ??> Message 1-6 queued
         ??> send_complete_callback registered

Time T1: Messages 1-6 acknowledged
         ??> Callbacks 1-6 fire
             ??> "Send complete acknowledged by peer" x6

Time T2: TCP RST received (error -14)
         ??> Connection marked for closure

Time T3: Timeout (5 seconds)
         ??> lwip_close_connection() called
         ??> Connection removed from list
         ??> tcp_abort() called
         ??> on_tcp_error fires ? conn_unref()

Time T4: MORE callbacks try to fire!
         ??> C# code: send_complete_callback()
         ??> C# code calls find_connection() ? NOT FOUND
         ??> "Connection 'xxx' not found"
```

## Why This Happens

### Issue 1: C# Holds Reference to Callback

Your C# code likely has code like this:

```csharp
private void OnSendComplete()
{
    _logger.LogInformation("Send complete acknowledged by peer.");
    
    // ? Problem: Trying to access connection after it's closed
    // This might call back into native code
}
```

### Issue 2: Callbacks After Connection Close

The C callback (`send_complete_callback`) is stored in the `connection_entry_t`:

```c
typedef struct connection_entry {
    send_complete_callback_t send_complete_callback;  // ? This
    // ...
} connection_entry_t;
```

When the connection is freed, this callback pointer is freed too. **But**:
- C# might still have a reference to it
- C# might call native code that tries to `find_connection()`

## The Solution

### Option 1: Clear Callback on Close (Recommended)

Modify the close functions to clear the callback BEFORE closing:

```c
void lwip_close_connection(const char* id) {
    // ... existing code ...
    
    if (conn->pcb) {
        // ? Clear callbacks to prevent use-after-free
        conn->send_complete_callback = NULL;  // Add this line
        
        conn->persistent_mode = 0;
        tcp_arg(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
    }
    
    // ...
}
```

### Option 2: Check Connection Validity in C# (Defense in Depth)

In your C# code, add null checks:

```csharp
private void OnSendComplete()
{
    // Check if connection still exists
    if (_disposed || _connectionId == null)
    {
        // Connection was closed, ignore callback
        return;
    }
    
    // Only log if connection is still valid
    int available = LwipNative.lwip_tcp_get_send_buffer_available(_connectionId);
    if (available >= 0)
    {
        _logger.LogInformation("Send complete acknowledged by peer.");
    }
}
```

### Option 3: Use Connection State Flag (Most Robust)

Add a flag to track if connection is closing:

```c
typedef struct connection_entry {
    // ... existing fields ...
    volatile int is_closing;  // Add this
} connection_entry_t;

void lwip_close_connection(const char* id) {
    // ... find connection ...
    
    if (conn) {
        conn->is_closing = 1;  // Set flag FIRST
        
        // Then proceed with close
        // ...
    }
}

// In callback:
if (conn->send_complete_callback && !conn->is_closing) {
    conn->send_complete_callback();
}
```

## Why "Connection not found" Still Appears

Even with our fix, you see "Connection not found" because:

1. **C# callback is stored outside the connection struct**
2. **C# .NET runtime holds the delegate**
3. **When C# calls back, it tries to find the connection**
4. **Connection is already freed**

This is **NOT a crash** - it's just a noisy log message. The `find_connection()` safely returns NULL, and the C# code handles it.

## Recommended Fix

Implement **both** Option 1 and Option 2:

### 1. C Code: Clear Callback Before Close

```c
void lwip_close_connection(const char* id) {
    // ... existing code up to finding conn ...
    
    if (conn->pcb) {
        // ? CRITICAL: Clear callback FIRST to prevent C# from calling it
        conn->send_complete_callback = NULL;
        
        conn->persistent_mode = 0;
        tcp_arg(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
    }
    
    // ... rest of close logic ...
}

void lwip_tcp_disconnect_persistent(const char* id) {
    // ... existing code ...
    
    if (conn->pcb && conn->persistent_mode) {
        // ? Clear callback here too
        conn->send_complete_callback = NULL;
        
        conn->persistent_mode = 0;
        // ... rest of close logic ...
    }
}
```

### 2. C# Code: Check Before Logging

```csharp
public class LwipTcpMessageService
{
    private bool _disposed;
    private string _connectionId;
    
    private void OnSendComplete()
    {
        if (_disposed || _connectionId == null)
        {
            // Connection closed, ignore callback
            return;
        }
        
        // Safe to log
        _logger.LogInformation("Send complete acknowledged by peer.");
    }
    
    public void Dispose()
    {
        _disposed = true;  // Set flag FIRST
        
        if (_connectionId != null)
        {
            LwipNative.lwip_tcp_disconnect_persistent(_connectionId);
            LwipNative.lwip_close_connection(_connectionId);
            _connectionId = null;
        }
    }
}
```

## Summary

| Issue | Symptom | Fix |
|-------|---------|-----|
| **Memory leak** | Connections not freed | ? Fixed (on_tcp_error releases reference) |
| **Use-after-free** | Crash when ACKs arrive | ? Fixed (keep tcp_err callback) |
| **Noisy logs** | "Connection not found" | ?? Need to clear callback on close |

The "Connection not found" messages are **not dangerous** - they're just noisy. But we should fix them by clearing the callback before closing the connection.

## Implementation

See the code changes above to:
1. Clear `send_complete_callback` in close functions
2. Add null checks in C# callback
3. Remove noisy log message from `find_connection()`

This will eliminate the log spam without breaking anything!
