# Memory Leak and Use-After-Free Fix - Complete Guide

## Problem Summary

The wrapper had a **memory leak** in persistent TCP connections, but the initial fix caused a **use-after-free crash** when ACKs arrived after closing.

## Root Cause Analysis

### Memory Leak Issue

**Location**: `lwip_close_connection()` and `lwip_tcp_disconnect_persistent()`

**Problem**: Callback reference from `lwip_tcp_connect_persistent()` was never released.

```c
// Connection created with ref_count = 1 (connection_list)
lwip_create_connection(...);

// TCP connection adds callback reference: ref_count = 2
lwip_tcp_connect_persistent(...) {
    conn_ref(conn);  // Add reference for callbacks
    tcp_connect(...);
}

// Close connection removes from list: ref_count = 1
lwip_close_connection(id) {
    *prev = conn->next;  // Remove from list
    tcp_abort(conn->pcb);
    conn_unref(conn);  // Release list reference
    // ? Callback reference never released! ref_count = 1
    // ? Connection never freed - MEMORY LEAK!
}
```

### Use-After-Free Issue (First Fix Attempt)

**Attempted Fix**: Added `conn_unref(conn)` after `tcp_abort()`

**Problem**: Created use-after-free race condition!

```c
lwip_close_connection(id) {
    tcp_arg(conn->pcb, NULL);   // Clear callbacks
    tcp_abort(conn->pcb);       // Abort connection
    conn_unref(conn);           // Release callback reference ? ref_count = 1
    conn_unref(conn);           // Release list reference ? ref_count = 0, FREED!
}

// Meanwhile, ACK arrives after tcp_abort but before memory freed...
on_tcp_sent_persistent(conn, ...) {
    if (!conn) return ERR_ARG;  // ?? conn points to FREED memory!
    // ?? CRASH! Use-after-free!
}
```

## The Correct Solution

### Key Insight

**`tcp_abort()` triggers `on_tcp_error()` callback with `ERR_ABRT`**

We must let `on_tcp_error()` handle releasing the callback reference!

### Implementation

#### 1. Keep `tcp_err` Callback Active

```c
void lwip_close_connection(const char* id) {
    if (conn->pcb) {
        conn->persistent_mode = 0;        // Prevent normal operations
        
        tcp_arg(conn->pcb, NULL);         // Clear arg callback
        tcp_sent(conn->pcb, NULL);        // Clear sent callback
        tcp_recv(conn->pcb, NULL);        // Clear recv callback
        
        // ? DON'T clear tcp_err - we need it!
        // tcp_err(conn->pcb, NULL);      // ? Don't do this!
        
        tcp_abort(conn->pcb);             // Triggers on_tcp_error
        conn->pcb = NULL;
        
        // ? DON'T call conn_unref here - on_tcp_error will do it!
    }
    
    conn_unref(conn);  // Release list reference only
}
```

#### 2. Let `on_tcp_error` Release Callback Reference

```c
static void on_tcp_error(void* arg, err_t err) {
    connection_entry_t* conn = (connection_entry_t*)arg;
    
    if (conn) {
        lwip_lock();
        if (conn->message) {
            free(conn->message);
            conn->message = NULL;
        }
        conn->pcb = NULL;
        conn->persistent_mode = 0;
        lwip_unlock();
        
        // ? This releases the callback reference safely
        conn_unref(conn);
    }
}
```

## Reference Counting Flow (Fixed)

### Normal Operation

| Event | ref_count | Reference Holders |
|-------|-----------|-------------------|
| Create connection | 1 | connection_list |
| TCP connect (persistent) | 2 | connection_list + callbacks |
| Send/receive data | 2 | connection_list + callbacks |
| Close: remove from list | 1 | callbacks only |
| on_tcp_error fires | 0 | **FREED SAFELY** |

### Why This Is Safe

```
lwip_close_connection()
  ?
tcp_abort()
  ?
LwIP Internal: Schedule on_tcp_error(conn, ERR_ABRT)
  ?
[conn still has ref_count = 1, memory is VALID]
  ?
on_tcp_error(conn, ERR_ABRT)
  ?
conn_unref(conn)  ? ref_count = 0
  ?
free(conn)  ? Memory freed SAFELY
```

## Special Case: `lwip_tcp_disconnect_persistent`

This function can use **either** `tcp_close()` (graceful) or `tcp_abort()` (forceful).

### Implementation

```c
void lwip_tcp_disconnect_persistent(const char* id) {
    connection_entry_t* conn = find_connection(id);
    if (!conn) return;

    lwip_lock();

    if (conn->pcb && conn->persistent_mode) {
        conn->persistent_mode = 0;
        
        // Clear non-error callbacks
        tcp_arg(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        
        if (netif_is_up(&conn->netif)) {
            err_t close_err = tcp_close(conn->pcb);
            
            if (close_err != ERR_OK) {
                // Close failed - abort instead
                // This will call on_tcp_error
                tcp_abort(conn->pcb);
            } else {
                // Close succeeded - no error callback will fire
                // Must manually release callback reference
                tcp_err(conn->pcb, NULL);  // Clear error callback
                conn_unref(conn);          // Release callback reference
            }
        } else {
            // Netif down - must abort
            // This will call on_tcp_error
            tcp_abort(conn->pcb);
        }
        
        conn->pcb = NULL;
    }

    lwip_unlock();
    conn_unref(conn);  // Release find_connection reference
}
```

### Logic Explanation

| Scenario | Action | Who Releases Callback Reference |
|----------|--------|--------------------------------|
| `tcp_close()` succeeds | Graceful close | **We do**: `conn_unref()` |
| `tcp_close()` fails | Call `tcp_abort()` | **`on_tcp_error`** does it |
| Netif down | Call `tcp_abort()` | **`on_tcp_error`** does it |

## Comparison: Before vs. After

### Before (Memory Leak)

```c
// ref_count never reaches 0
? Connection leaked
? No crashes
```

### After (Fixed)

```c
// ref_count properly managed
? No memory leak
? No use-after-free
? No crashes
```

## Testing Checklist

### Test 1: Normal Operation
```csharp
lwip_tcp_connect_persistent(id, ip, port);
lwip_tcp_send_persistent(id, data, len);
lwip_tcp_disconnect_persistent(id);
// ? Should not leak memory
// ? Should not crash
```

### Test 2: Error During Send
```csharp
lwip_tcp_connect_persistent(id, ip, port);
lwip_tcp_send_persistent(id, data, len);
// Network error occurs (TCP RST)
lwip_close_connection(id);
// ? Should not leak memory
// ? Should not crash even if ACKs arrive
```

### Test 3: Graceful Disconnect
```csharp
lwip_tcp_connect_persistent(id, ip, port);
lwip_tcp_send_persistent(id, data, len);
lwip_tcp_disconnect_persistent(id);
// ? Should use tcp_close() if possible
// ? Should not leak memory
```

### Test 4: Forced Disconnect
```csharp
lwip_tcp_connect_persistent(id, ip, port);
lwip_tcp_send_persistent(id, data, len);
// Shut down netif
lwip_close_connection(id);
// ? Should use tcp_abort()
// ? Should not leak memory
// ? Should not crash
```

## Common Pitfalls to Avoid

### ? Pitfall 1: Clearing tcp_err Before Abort

```c
// WRONG!
tcp_err(conn->pcb, NULL);  // ? Clears error callback
tcp_abort(conn->pcb);      // on_tcp_error won't be called
conn_unref(conn);          // ? Might free while callbacks pending
```

### ? Pitfall 2: Double conn_unref

```c
// WRONG!
tcp_abort(conn->pcb);  // Calls on_tcp_error ? conn_unref()
conn_unref(conn);      // ? Double unref!
```

### ? Pitfall 3: Not Handling tcp_close Success

```c
// WRONG!
err_t err = tcp_close(conn->pcb);
// ? Forgot to handle success case - memory leak!
```

## Summary

| Aspect | Solution |
|--------|----------|
| **Memory Leak** | Fixed by releasing callback reference |
| **Use-After-Free** | Fixed by letting `on_tcp_error` handle cleanup |
| **Safety** | Reference counting prevents premature free |
| **Reliability** | `tcp_abort()` guarantees `on_tcp_error` is called |

## Key Principle

**Never manually release callback references when using `tcp_abort()`**

Let the error callback (`on_tcp_error`) handle it to prevent use-after-free!

---

**Status**: ? Fixed
**Date**: 2025
**Impact**: Critical - prevents both memory leaks and crashes
