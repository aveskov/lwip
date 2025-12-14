# Application Lifecycle Guide - Initialization and Cleanup

## Overview

Proper initialization and cleanup of the lwIP stack is critical for:
- ? **Memory leak prevention** - Free all allocated resources
- ? **Clean shutdown** - Gracefully close all connections
- ? **Resource management** - Properly cleanup TCP/UDP/SSL state
- ? **Reusability** - Allow reinitialization after cleanup

---

## ?? Complete Lifecycle

```
Application Start
       ?
lwip_init_stack_global()      ? Initialize lwIP
       ?
lwip_ssl_init_global()         ? Initialize SSL (if using SSL)
       ?
Start polling thread           ? Start lwip_poll() loop
       ?
Create connections
       ?
Send/Receive data
       ?
Stop polling thread            ? STOP polling FIRST (critical!)
       ?
lwip_ssl_cleanup_global()      ? Cleanup SSL (if using SSL)
       ?
lwip_cleanup_stack_global()    ? Cleanup lwIP
       ?
Application Exit
```

---

## ?? Function Reference

### Initialization Functions

```c
// Initialize lwIP stack (call once at startup)
void lwip_init_stack_global(void);

// Initialize SSL/TLS support (call once if using SSL)
void lwip_ssl_init_global(void);
```

### Cleanup Functions

```c
// Cleanup SSL/TLS (call before lwIP cleanup if using SSL)
void lwip_ssl_cleanup_global(void);

// Cleanup entire lwIP stack (call once at shutdown)
void lwip_cleanup_stack_global(void);

// Close individual connection
void lwip_close_connection(const char* id);

// Close SSL connection
void lwip_ssl_close_connection(const char* id);
```

---

## ?? C# Implementation Examples

### Example 1: Complete Application Lifecycle

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern void lwip_init_stack_global();

[DllImport("lwip_wrapper.dll")]
private static extern void lwip_cleanup_stack_global();

[DllImport("lwip_wrapper.dll")]
private static extern void lwip_ssl_init_global();

[DllImport("lwip_wrapper.dll")]
private static extern void lwip_ssl_cleanup_global();

public class Application
{
    private List<string> _activeConnections = new List<string>();
    
    public async Task RunAsync()
    {
        try
        {
            // ? STEP 1: Initialize lwIP
            Console.WriteLine("Initializing lwIP...");
            lwip_init_stack_global();
            
            // ? STEP 2: Initialize SSL (if needed)
            Console.WriteLine("Initializing SSL...");
            lwip_ssl_init_global();
            
            // STEP 3: Create connections
            Console.WriteLine("Creating connections...");
            for (int i = 0; i < 5; i++)
            {
                string connId = $"conn_{i}";
                CreateConnection(connId);
                _activeConnections.Add(connId);
            }
            
            // STEP 4: Run application
            Console.WriteLine("Running application...");
            await DoWork();
        }
        finally
        {
            // ? STEP 5: Cleanup SSL
            Console.WriteLine("Cleaning up SSL...");
            lwip_ssl_cleanup_global();
            
            // ? STEP 6: Cleanup lwIP (closes all connections)
            Console.WriteLine("Cleaning up lwIP...");
            lwip_cleanup_stack_global();
            
            Console.WriteLine("Shutdown complete");
        }
    }
}
```

### Example 2: IHostedService Pattern (ASP.NET Core)

```csharp
public class LwipHostedService : IHostedService
{
    private readonly ILogger<LwipHostedService> _logger;
    private CancellationTokenSource _pollingCts;
    private Task _pollingTask;
    
    public LwipHostedService(ILogger<LwipHostedService> logger)
    {
        _logger = logger;
    }
    
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("? Starting lwIP service...");
        
        // Initialize lwIP
        lwip_init_stack_global();
        
        // Initialize SSL
        lwip_ssl_init_global();
        
        // ? Start polling thread
        _pollingCts = new CancellationTokenSource();
        _pollingTask = Task.Run(() => PollLoop(_pollingCts.Token));
        
        _logger.LogInformation("? lwIP service started");
        return Task.CompletedTask;
    }
    
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("? Stopping lwIP service...");
        
        // ? STEP 1: Stop polling thread FIRST
        _logger.LogInformation("Stopping polling thread...");
        _pollingCts?.Cancel();
        
        if (_pollingTask != null)
        {
            await _pollingTask;  // Wait for polling to stop
        }
        _logger.LogInformation("? Polling stopped");
        
        // ? STEP 2: Now safe to cleanup
        _logger.LogInformation("Cleaning up SSL...");
        lwip_ssl_cleanup_global();
        
        _logger.LogInformation("Cleaning up lwIP...");
        lwip_cleanup_stack_global();
        
        _logger.LogInformation("? lwIP service stopped");
    }
    
    private async Task PollLoop(CancellationToken ct)
    {
        _logger.LogInformation("Polling thread started");
        
        while (!ct.IsCancellationRequested)
        {
            lwip_poll();
            await Task.Delay(10, ct);
        }
        
        _logger.LogInformation("Polling thread exited");
    }
}

// Startup.cs or Program.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddHostedService<LwipHostedService>();
}
```

### Example 3: IDisposable Pattern

```csharp
public class LwipManager : IDisposable
{
    private bool _initialized = false;
    private bool _disposed = false;
    
    public void Initialize()
    {
        if (_initialized)
            throw new InvalidOperationException("Already initialized");
        
        Console.WriteLine("? Initializing lwIP stack...");
        lwip_init_stack_global();
        
        Console.WriteLine("? Initializing SSL...");
        lwip_ssl_init_global();
        
        _initialized = true;
        Console.WriteLine("? Initialization complete");
    }
    
    public void Dispose()
    {
        if (_disposed)
            return;
        
        Console.WriteLine("? Disposing lwIP manager...");
        
        if (_initialized)
        {
            // Cleanup SSL
            Console.WriteLine("  Cleaning up SSL...");
            lwip_ssl_cleanup_global();
            
            // Cleanup lwIP
            Console.WriteLine("  Cleaning up lwIP...");
            lwip_cleanup_stack_global();
        }
        
        _disposed = true;
        Console.WriteLine("? Disposal complete");
    }
}

// Usage
using (var lwip = new LwipManager())
{
    lwip.Initialize();
    
    // Use lwIP...
    
}  // Automatic cleanup on dispose
```

### Example 4: Graceful Shutdown with Pending ACKs

```csharp
public class GracefulShutdownExample
{
    private List<string> _connections = new List<string>();
    private bool _pollingRunning = true;
    private Task _pollingTask;
    
    public void Start()
    {
        // Initialize
        lwip_init_stack_global();
        lwip_ssl_init_global();
        
        // ? Start polling thread
        _pollingTask = Task.Run(PollLoop);
        
        // Create connections...
    }
    
    public async Task ShutdownGracefully()
    {
        Console.WriteLine("?? Initiating graceful shutdown...");
        
        // Step 1: Wait for pending ACKs on all connections
        Console.WriteLine("Step 1: Waiting for pending ACKs...");
        await WaitForAllAcks(TimeSpan.FromSeconds(10));
        
        // Step 2: Close all SSL connections individually (optional but cleaner)
        Console.WriteLine("Step 2: Closing SSL connections...");
        foreach (var connId in _connections)
        {
            lwip_ssl_disconnect_persistent(connId);
        }
        
        // ? Step 3: Stop polling thread FIRST (critical!)
        Console.WriteLine("Step 3: Stopping polling thread...");
        _pollingRunning = false;
        await _pollingTask;  // Wait for polling to exit
        Console.WriteLine("? Polling stopped");
        
        // ? Step 4: Cleanup SSL
        Console.WriteLine("Step 4: Cleaning up SSL...");
        lwip_ssl_cleanup_global();
        
        // ? Step 5: Cleanup lwIP (closes any remaining connections)
        Console.WriteLine("Step 5: Cleaning up lwIP...");
        lwip_cleanup_stack_global();
        
        Console.WriteLine("? Graceful shutdown complete");
    }
    
    private async Task PollLoop()
    {
        while (_pollingRunning)
        {
            lwip_poll();
            await Task.Delay(10);
        }
    }
    
    private async Task WaitForAllAcks(TimeSpan timeout)
    {
        var stopwatch = Stopwatch.StartNew();
        
        while (stopwatch.Elapsed < timeout)
        {
            bool allClear = true;
            
            foreach (var connId in _connections)
            {
                int pending = lwip_ssl_get_pending_ack_count(connId);
                if (pending > 0)
                {
                    Console.WriteLine($"  {connId}: {pending} ACKs pending");
                    allClear = false;
                }
            }
            
            if (allClear)
            {
                Console.WriteLine("  ? All ACKs received");
                return;
            }
            
            // Note: lwip_poll() is called by polling thread, not here
            await Task.Delay(100);
        }
        
        Console.WriteLine("  ?? Timeout waiting for ACKs - proceeding anyway");
    }
}
```

### Example 5: Windows Service Pattern

```csharp
public class LwipWindowsService : ServiceBase
{
    public LwipWindowsService()
    {
        ServiceName = "LwipService";
    }
    
    protected override void OnStart(string[] args)
    {
        try
        {
            // ? Initialize on service start
            EventLog.WriteEntry("Initializing lwIP...", EventLogEntryType.Information);
            
            lwip_init_stack_global();
            lwip_ssl_init_global();
            
            EventLog.WriteEntry("lwIP initialized successfully", EventLogEntryType.Information);
            
            // Start your worker threads...
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry($"Failed to initialize: {ex}", EventLogEntryType.Error);
            throw;
        }
    }
    
    protected override void OnStop()
    {
        try
        {
            // ? Cleanup on service stop
            EventLog.WriteEntry("Stopping lwIP service...", EventLogEntryType.Information);
            
            // Stop worker threads...
            
            // Cleanup resources
            lwip_ssl_cleanup_global();
            lwip_cleanup_stack_global();
            
            EventLog.WriteEntry("lwIP service stopped", EventLogEntryType.Information);
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry($"Error during shutdown: {ex}", EventLogEntryType.Error);
        }
    }
}
```

### Example 6: Console Application with Ctrl+C Handler

```csharp
public class ConsoleApplication
{
    private static bool _running = true;
    private static Task _pollingTask;
    
    public static async Task Main(string[] args)
    {
        // Setup Ctrl+C handler
        Console.CancelKeyPress += OnCancelKeyPress;
        
        try
        {
            // ? STEP 1: Initialize
            Console.WriteLine("? Initializing lwIP...");
            lwip_init_stack_global();
            lwip_ssl_init_global();
            
            // ? STEP 2: Start polling thread
            Console.WriteLine("? Starting polling thread...");
            _pollingTask = Task.Run(PollLoop);
            
            // STEP 3: Run application
            Console.WriteLine("Running... Press Ctrl+C to stop");
            await DoWork();
        }
        finally
        {
            // ? STEP 4: Stop polling FIRST (critical!)
            Console.WriteLine("\n? Stopping polling thread...");
            _running = false;
            await _pollingTask;  // Wait for polling to stop
            Console.WriteLine("? Polling stopped");
            
            // ? STEP 5: Now safe to cleanup
            Console.WriteLine("? Cleaning up SSL...");
            lwip_ssl_cleanup_global();
            
            Console.WriteLine("? Cleaning up lwIP...");
            lwip_cleanup_stack_global();
            
            Console.WriteLine("? Cleanup complete");
        }
    }
    
    private static void OnCancelKeyPress(object sender, ConsoleCancelEventArgs e)
    {
        Console.WriteLine("\n?? Shutdown signal received...");
        e.Cancel = true;  // Prevent immediate termination
        _running = false;  // Signal polling to stop
    }
    
    private static async Task PollLoop()
    {
        Console.WriteLine("Polling thread started");
        while (_running)
        {
            lwip_poll();
            await Task.Delay(10);
        }
        Console.WriteLine("Polling thread exited");
    }
    
    private static async Task DoWork()
    {
        while (_running)
        {
            // Your application logic here
            await Task.Delay(1000);
        }
    }
}
```

---

## ?? Correct Shutdown Sequence

### ? RIGHT: Stop Polling First

```csharp
// Step 1: Signal polling to stop
_running = false;

// Step 2: Wait for polling thread to exit
await _pollingTask;

// Step 3: Now safe to cleanup
lwip_ssl_cleanup_global();
lwip_cleanup_stack_global();
```

### ? WRONG: Cleanup While Polling

```csharp
// ? DON'T DO THIS!
lwip_cleanup_stack_global();  // Cleanup starts
// ... polling thread still running ...
lwip_poll();  // CRASH! Accessing freed memory
```

### ? WRONG: Poll After Cleanup

```csharp
// ? DON'T DO THIS!
_running = false;
lwip_cleanup_stack_global();  // Cleanup
await _pollingTask;           // Polling might call lwip_poll() after cleanup
// CRASH! lwIP not initialized
```

---

## ?? CRITICAL: Stop Polling Before Cleanup!

**The polling thread MUST be stopped BEFORE calling cleanup functions!**

### Why?
- ? If polling continues during cleanup ? **crash** (accessing freed memory)
- ? If polling continues after cleanup ? **crash** (lwIP not initialized)
- ? Stop polling ? wait for thread exit ? then cleanup safely

---

## ?? What `lwip_cleanup_stack_global()` Does

```
1. Count active connections
   ?
2. Close all connections one by one
   - Calls lwip_close_connection() for each
   - Closes TCP/UDP connections
   - Removes network interfaces
   - Frees ACK queues
   ?
3. Cleanup lwIP lock
   - Deletes critical section
   - Marks as not initialized
   ?
4. All resources freed
```

### Detailed Steps

```c
lwip_cleanup_stack_global() {
    // 1. Lock and count connections
    int count = count_connections();
    
    // 2. Close each connection
    for each connection {
        - Close TCP PCB (tcp_close or tcp_abort)
        - Close UDP PCB (udp_remove)
        - Remove netif (netif_remove)
        - Free ACK queue entries
        - Free connection ID
        - Free connection structure
    }
    
    // 3. Cleanup lock (marks as not initialized)
    DeleteCriticalSection();
    lwip_initialized = 0;
}
```

---

## ?? Best Practices

### ? DO:

1. **Initialize once at startup**
```csharp
// At application startup
lwip_init_stack_global();
lwip_ssl_init_global();
```

2. **Cleanup once at shutdown**
```csharp
// At application shutdown
lwip_ssl_cleanup_global();      // SSL first
lwip_cleanup_stack_global();    // Then lwIP
```

3. **Use try/finally for guaranteed cleanup**
```csharp
try {
    lwip_init_stack_global();
    // ... use lwIP ...
} finally {
    lwip_cleanup_stack_global();  // ? Always execute
}
```

4. **Wait for pending ACKs before cleanup** (optional but cleaner)
```csharp
await WaitForAllAcks();
lwip_cleanup_stack_global();
```

5. **Handle Ctrl+C gracefully**
```csharp
Console.CancelKeyPress += (s, e) => {
    e.Cancel = true;
    lwip_cleanup_stack_global();
};
```

### ? DON'T:

1. **Don't initialize multiple times**
```csharp
lwip_init_stack_global();
lwip_init_stack_global();  // ? DON'T - already initialized
```

2. **Don't forget cleanup**
```csharp
lwip_init_stack_global();
// ... use lwIP ...
// ? Missing: lwip_cleanup_stack_global();
// Result: Memory leaks!
```

3. **Don't cleanup in wrong order**
```csharp
lwip_cleanup_stack_global();    // ? WRONG ORDER
lwip_ssl_cleanup_global();      // SSL should be first
```

4. **Don't use lwIP after cleanup**
```csharp
lwip_cleanup_stack_global();
lwip_tcp_send(...);  // ? DON'T - already cleaned up
```

---

## ?? Troubleshooting

### Issue: Memory leaks after application exit

**Solution**: Ensure cleanup is called
```csharp
try {
    lwip_init_stack_global();
    // ... use lwIP ...
} finally {
    lwip_cleanup_stack_global();  // ? Guaranteed cleanup
}
```

### Issue: Application hangs on shutdown

**Solution**: Set timeout for ACK waiting
```csharp
var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
try {
    await WaitForAllAcks(cts.Token);
} catch (OperationCanceledException) {
    Console.WriteLine("Timeout - forcing shutdown");
}
lwip_cleanup_stack_global();
```

### Issue: "Connection not found" errors during cleanup

**Solution**: Normal - connections already closed
```csharp
// This is OK - lwip_cleanup_stack_global() handles it
lwip_cleanup_stack_global();  // May print "Connection not found" but that's OK
```

### Issue: Crash on reinitialize after cleanup

**Solution**: Ensure full cleanup before reinitialize
```csharp
// First cleanup
lwip_ssl_cleanup_global();
lwip_cleanup_stack_global();

// Wait a bit (optional)
await Task.Delay(100);

// Then reinitialize
lwip_init_stack_global();
lwip_ssl_init_global();
```

---

## ?? Resource Cleanup Summary

### What Gets Cleaned Up

| Resource | Cleanup Function | Details |
|----------|-----------------|---------|
| **TCP connections** | `lwip_cleanup_stack_global()` | All TCP PCBs closed |
| **UDP connections** | `lwip_cleanup_stack_global()` | All UDP PCBs removed |
| **SSL contexts** | `lwip_ssl_cleanup_global()` | SSL_CTX and SSL objects freed |
| **Network interfaces** | `lwip_cleanup_stack_global()` | All netifs removed |
| **ACK queues** | `lwip_cleanup_stack_global()` | All pending ACK entries freed |
| **Connection IDs** | `lwip_cleanup_stack_global()` | All ID strings freed |
| **Critical sections** | `lwip_cleanup_stack_global()` | Windows CRITICAL_SECTION deleted |

---

## ? Complete Checklist

Before application exit:

- [ ] Stop accepting new connections
- [ ] Stop sending new messages
- [ ] Wait for pending ACKs (optional, max 5-10 seconds)
- [ ] ? **STOP POLLING THREAD** (critical - must be first!)
- [ ] Wait for polling thread to exit completely
- [ ] Close individual connections (optional - cleanup does this)
- [ ] Call `lwip_ssl_cleanup_global()` (if using SSL)
- [ ] Call `lwip_cleanup_stack_global()`
- [ ] Verify no lwIP calls after cleanup

---

## ?? Common Shutdown Mistakes

### ? Mistake 1: Cleanup Before Stopping Polling

```csharp
// ? WRONG - Will crash!
lwip_cleanup_stack_global();  // Start cleanup
// ... polling thread still running ...
lwip_poll();  // CRASH! Memory freed
```

**Fix**: Stop polling first
```csharp
// ? RIGHT
_running = false;
await _pollingTask;           // Wait for polling to stop
lwip_cleanup_stack_global();  // Now safe
```

### ? Mistake 2: Not Waiting for Polling Thread

```csharp
// ? WRONG - Race condition!
_running = false;             // Signal stop
lwip_cleanup_stack_global();  // But thread might still be polling!
```

**Fix**: Wait for thread exit
```csharp
// ? RIGHT
_running = false;
await _pollingTask;           // Wait for thread to exit
lwip_cleanup_stack_global();  // Now safe
```

### ? Mistake 3: Calling lwip_poll() in Multiple Threads

```csharp
// ? WRONG - Not thread-safe!
Task.Run(() => { while(true) lwip_poll(); });
Task.Run(() => { while(true) lwip_poll(); });  // Second thread!
```

**Fix**: Single polling thread only
```csharp
// ? RIGHT - One polling thread
_pollingTask = Task.Run(() => {
    while (_running) {
        lwip_poll();
        Thread.Sleep(10);
    }
});
```

---

## ?? Summary

### Minimal Pattern

```csharp
public class MinimalExample
{
    public void Run()
    {
        try
        {
            // ? Initialize
            lwip_init_stack_global();
            
            // Use lwIP...
        }
        finally
        {
            // ? Cleanup
            lwip_cleanup_stack_global();
        }
    }
}
```

### Full Pattern (with SSL)

```csharp
public class FullExample
{
    public async Task Run()
    {
        try
        {
            // ? Initialize
            lwip_init_stack_global();
            lwip_ssl_init_global();
            
            // Use lwIP and SSL...
            
            // Optional: Wait for ACKs
            await WaitForAllAcks();
        }
        finally
        {
            // ? Cleanup (reverse order)
            lwip_ssl_cleanup_global();      // SSL first
            lwip_cleanup_stack_global();    // lwIP last
        }
    }
}
```

**Result**: Zero memory leaks, clean shutdown, ready for reinitialize! ??
