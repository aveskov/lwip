# Application Shutdown Sequence - Complete Guide

## ?? The Golden Rule

**Stop polling BEFORE cleanup!**

```
? WRONG: Cleanup ? Stop Polling = CRASH
? RIGHT: Stop Polling ? Wait ? Cleanup = SAFE
```

---

## ?? Complete Shutdown Checklist

### Step-by-Step Shutdown

```
1. ? Stop accepting new work
   ?
2. ? Wait for pending ACKs (optional, max 5-10s)
   ?
3. ?? STOP POLLING THREAD (critical!)
   ?
4. ??  WAIT for polling thread to exit
   ?
5. ?? Cleanup SSL (if using)
   ?
6. ?? Cleanup lwIP
   ?
7. ? Application exit
```

---

## ?? Complete C# Example

```csharp
public class Application
{
    private bool _running = false;
    private Task _pollingTask;
    private List<string> _connections = new List<string>();
    
    public async Task RunAsync()
    {
        try
        {
            // ===== STARTUP =====
            
            // Step 1: Initialize lwIP
            Console.WriteLine("1. Initializing lwIP...");
            lwip_init_stack_global();
            lwip_ssl_init_global();
            
            // Step 2: Start polling thread
            Console.WriteLine("2. Starting polling thread...");
            _running = true;
            _pollingTask = Task.Run(PollLoop);
            
            // Step 3: Create connections and do work
            Console.WriteLine("3. Creating connections...");
            CreateConnections();
            
            Console.WriteLine("4. Running application...");
            await DoWork();
        }
        finally
        {
            // ===== SHUTDOWN =====
            await ShutdownGracefully();
        }
    }
    
    private async Task ShutdownGracefully()
    {
        Console.WriteLine("\n?? Starting graceful shutdown...");
        
        // Step 1: Stop accepting new work
        Console.WriteLine("Step 1: Stopping new work...");
        // Your code here...
        
        // Step 2: Wait for pending ACKs (optional but recommended)
        Console.WriteLine("Step 2: Waiting for pending ACKs...");
        await WaitForAllAcks(TimeSpan.FromSeconds(5));
        
        // Step 3: STOP POLLING THREAD (CRITICAL!)
        Console.WriteLine("Step 3: Stopping polling thread...");
        _running = false;
        
        // Step 4: WAIT for polling thread to exit
        Console.WriteLine("Step 4: Waiting for polling to exit...");
        if (_pollingTask != null)
        {
            await _pollingTask;
        }
        Console.WriteLine("? Polling stopped");
        
        // Step 5: Close individual connections (optional - cleanup does this)
        Console.WriteLine("Step 5: Closing connections...");
        foreach (var connId in _connections)
        {
            lwip_ssl_disconnect_persistent(connId);
        }
        
        // Step 6: Cleanup SSL
        Console.WriteLine("Step 6: Cleaning up SSL...");
        lwip_ssl_cleanup_global();
        
        // Step 7: Cleanup lwIP
        Console.WriteLine("Step 7: Cleaning up lwIP...");
        lwip_cleanup_stack_global();
        
        Console.WriteLine("? Shutdown complete!");
    }
    
    private async Task PollLoop()
    {
        Console.WriteLine("Polling thread started (100Hz)");
        
        while (_running)
        {
            try
            {
                lwip_poll();
                await Task.Delay(10);  // 100Hz
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Polling error: {ex}");
            }
        }
        
        Console.WriteLine("Polling thread exited");
    }
    
    private async Task WaitForAllAcks(TimeSpan timeout)
    {
        var stopwatch = Stopwatch.StartNew();
        
        while (stopwatch.Elapsed < timeout)
        {
            bool allClear = true;
            int totalPending = 0;
            
            foreach (var connId in _connections)
            {
                int pending = lwip_ssl_get_pending_ack_count(connId);
                if (pending > 0)
                {
                    totalPending += pending;
                    allClear = false;
                }
            }
            
            if (allClear)
            {
                Console.WriteLine("  ? All ACKs received");
                return;
            }
            
            Console.WriteLine($"  Waiting... {totalPending} ACKs pending");
            await Task.Delay(100);
        }
        
        Console.WriteLine("  ?? Timeout - proceeding anyway");
    }
}
```

---

## ?? Critical Mistakes to Avoid

### ? Mistake 1: Cleanup Before Stopping Polling

```csharp
// ? CRASH GUARANTEED!
lwip_cleanup_stack_global();  // Starts freeing memory
// ... polling thread still running ...
lwip_poll();  // BOOM! Accessing freed memory
```

**Fix**:
```csharp
// ? RIGHT
_running = false;
await _pollingTask;
lwip_cleanup_stack_global();
```

### ? Mistake 2: Not Waiting for Polling to Exit

```csharp
// ? RACE CONDITION!
_running = false;
lwip_cleanup_stack_global();  // Polling might still be running!
```

**Fix**:
```csharp
// ? RIGHT
_running = false;
await _pollingTask;  // WAIT for thread to exit
lwip_cleanup_stack_global();
```

### ? Mistake 3: Wrong Cleanup Order

```csharp
// ? WRONG ORDER!
_running = false;
await _pollingTask;
lwip_cleanup_stack_global();  // lwIP first
lwip_ssl_cleanup_global();    // SSL last
```

**Fix**:
```csharp
// ? RIGHT ORDER
_running = false;
await _pollingTask;
lwip_ssl_cleanup_global();    // SSL first
lwip_cleanup_stack_global();  // lwIP last
```

### ? Mistake 4: Forgot to Start Polling

```csharp
// ? FORGOT POLLING!
lwip_init_stack_global();
// Missing: Start polling thread
// Result: Timeouts, keep-alive fails, retransmissions don't work
```

**Fix**:
```csharp
// ? RIGHT
lwip_init_stack_global();
_pollingTask = Task.Run(PollLoop);  // Start polling
```

---

## ?? Quick Reference: Shutdown Order

### Minimal (No SSL)

```csharp
1. _running = false;           // Signal stop
2. await _pollingTask;         // Wait for polling to exit
3. lwip_cleanup_stack_global(); // Cleanup
```

### With SSL

```csharp
1. _running = false;            // Signal stop
2. await _pollingTask;          // Wait for polling to exit
3. lwip_ssl_cleanup_global();   // Cleanup SSL first
4. lwip_cleanup_stack_global(); // Cleanup lwIP last
```

### With ACK Wait

```csharp
1. await WaitForAllAcks();      // Wait for ACKs (optional)
2. _running = false;            // Signal stop
3. await _pollingTask;          // Wait for polling to exit
4. lwip_ssl_cleanup_global();   // Cleanup SSL
5. lwip_cleanup_stack_global(); // Cleanup lwIP
```

---

## ?? What Each Step Does

### Stop Polling (`_running = false`)
- Signals polling loop to exit on next iteration
- Does NOT block - returns immediately
- Polling continues until it checks `_running` flag

### Wait for Polling (`await _pollingTask`)
- **Blocks** until polling thread exits
- Ensures no more `lwip_poll()` calls
- **Critical** - must complete before cleanup

### Cleanup SSL (`lwip_ssl_cleanup_global()`)
- Closes all SSL connections
- Frees SSL_CTX and SSL objects
- Deletes SSL critical section

### Cleanup lwIP (`lwip_cleanup_stack_global()`)
- Closes all TCP/UDP connections
- Removes all network interfaces
- Frees all ACK queues
- Deletes lwIP critical section
- Marks as not initialized

---

## ?? Typical Shutdown Timeline

```
Time  | Action
------|------------------------------------------
0ms   | _running = false (signal)
10ms  | Polling loop checks _running, exits
10ms  | await _pollingTask returns
11ms  | lwip_ssl_cleanup_global() starts
50ms  | SSL cleanup complete
51ms  | lwip_cleanup_stack_global() starts
100ms | lwIP cleanup complete
100ms | Application exit
```

**Total: ~100ms for clean shutdown**

---

## ?? Debugging Shutdown Issues

### Issue: Application hangs on exit

**Possible causes**:
1. Polling thread not exiting
2. Waiting for ACKs that never arrive
3. Deadlock in cleanup

**Debug**:
```csharp
// Add timeouts
var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
try {
    await _pollingTask.WaitAsync(cts.Token);
} catch (TimeoutException) {
    Console.WriteLine("ERROR: Polling didn't stop!");
}
```

### Issue: Crash on exit

**Possible causes**:
1. Cleanup called while polling still running
2. Multiple cleanup calls
3. Using lwIP after cleanup

**Debug**:
```csharp
// Add logging
Console.WriteLine("Before polling stop");
_running = false;
await _pollingTask;
Console.WriteLine("After polling stop");
lwip_cleanup_stack_global();
Console.WriteLine("After cleanup");
```

### Issue: Memory leaks

**Possible causes**:
1. Forgot to call cleanup
2. Cleanup crashed before completing
3. Connections not properly closed

**Debug**:
```csharp
// Use try/finally
try {
    // ... use lwIP ...
} finally {
    _running = false;
    await _pollingTask;
    lwip_cleanup_stack_global();  // Always executes
}
```

---

## ? Success Criteria

After shutdown completes:

- ? Polling thread exited
- ? All connections closed
- ? All ACK queues freed
- ? All memory released
- ? No crashes or hangs
- ? Can reinitialize if needed

---

## ?? Summary

### The Essential Shutdown Sequence

```csharp
// 1. Stop polling
_running = false;

// 2. WAIT for polling to exit
await _pollingTask;

// 3. Cleanup (reverse order of init)
lwip_ssl_cleanup_global();
lwip_cleanup_stack_global();
```

### Remember:

1. **Always stop polling BEFORE cleanup**
2. **Wait for thread exit** - don't assume it stopped
3. **Cleanup in reverse order** - SSL then lwIP
4. **Use try/finally** - ensure cleanup happens
5. **Handle timeouts** - don't hang forever

**Follow these rules = Clean, safe shutdown!** ??

---

## ?? Related Documentation

- `APPLICATION_LIFECYCLE_GUIDE.md` - Complete lifecycle examples
- `POLLING_THREAD_GUIDE.md` - Detailed polling information
- `LIFECYCLE_QUICK_REF.md` - Quick reference guide
- `TCP_KEEPALIVE_GUIDE.md` - Keep-alive configuration

---

**Last Updated**: 2024
