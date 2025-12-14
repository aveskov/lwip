# Quick Reference: Initialization and Cleanup

## ?? Minimal Usage

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern void lwip_init_stack_global();

[DllImport("lwip_wrapper.dll")]
private static extern void lwip_cleanup_stack_global();

// Use it
try {
    lwip_init_stack_global();     // ? Initialize
    // ... use lwIP ...
} finally {
    lwip_cleanup_stack_global();  // ? Cleanup
}
```

---

## ?? Function Calls Order

### Startup (With SSL)
```csharp
1. lwip_init_stack_global();      // Initialize lwIP
2. lwip_ssl_init_global();        // Initialize SSL
3. // Create connections and use...
```

### Shutdown (With SSL)
```csharp
1. // Stop polling thread FIRST!
2. _running = false;
3. await _pollingTask;             // Wait for polling to exit
4. // Optional: Wait for pending ACKs
5. lwip_ssl_cleanup_global();      // Cleanup SSL first
6. lwip_cleanup_stack_global();    // Cleanup lwIP last
```

### Startup (No SSL)
```csharp
1. lwip_init_stack_global();       // Initialize lwIP
2. _pollingTask = Task.Run(Poll);  // Start polling
3. // Create connections and use...
```

### Shutdown (No SSL)
```csharp
1. // Stop polling thread FIRST!
2. _running = false;
3. await _pollingTask;             // Wait for polling to exit
4. // Optional: Wait for pending ACKs
5. lwip_cleanup_stack_global();    // Cleanup lwIP
```

---

## ?? Common Patterns

### Pattern 1: Console Application
```csharp
static bool _running = true;
static Task _pollingTask;

static void Main()
{
    try {
        lwip_init_stack_global();
        
        // ? Start polling thread
        _pollingTask = Task.Run(() => {
            while (_running) {
                lwip_poll();
                Thread.Sleep(10);
            }
        });
        
        DoWork();
    } finally {
        // ? Stop polling FIRST
        _running = false;
        _pollingTask.Wait();
        
        // Then cleanup
        lwip_cleanup_stack_global();
    }
}
```

### Pattern 2: IDisposable
```csharp
public class LwipManager : IDisposable
{
    private bool _running = true;
    private Task _pollingTask;
    
    public LwipManager()
    {
        lwip_init_stack_global();
        
        // ? Start polling
        _pollingTask = Task.Run(() => {
            while (_running) {
                lwip_poll();
                Thread.Sleep(10);
            }
        });
    }
    
    public void Dispose()
    {
        // ? Stop polling FIRST
        _running = false;
        _pollingTask?.Wait();
        
        // Then cleanup
        lwip_cleanup_stack_global();
    }
}

using (var lwip = new LwipManager()) {
    // Use it
}
```

### Pattern 3: IHostedService (ASP.NET Core)
```csharp
public class LwipService : IHostedService
{
    private CancellationTokenSource _cts;
    private Task _pollingTask;
    
    public Task StartAsync(CancellationToken ct)
    {
        lwip_init_stack_global();
        
        // ? Start polling
        _cts = new CancellationTokenSource();
        _pollingTask = Task.Run(() => PollLoop(_cts.Token));
        
        return Task.CompletedTask;
    }
    
    public async Task StopAsync(CancellationToken ct)
    {
        // ? Stop polling FIRST
        _cts?.Cancel();
        if (_pollingTask != null)
            await _pollingTask;
        
        // Then cleanup
        lwip_cleanup_stack_global();
    }
    
    private async Task PollLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            lwip_poll();
            await Task.Delay(10, ct);
        }
    }
}
```

### Pattern 4: Ctrl+C Handler
```csharp
static bool _running = true;
static Task _pollingTask;

static void Main()
{
    Console.CancelKeyPress += (s, e) => {
        e.Cancel = true;
        _running = false;  // Signal polling to stop
    };
    
    lwip_init_stack_global();
    
    // ? Start polling
    _pollingTask = Task.Run(() => {
        while (_running) {
            lwip_poll();
            Thread.Sleep(10);
        }
    });
    
    // Wait for Ctrl+C
    while (_running) {
        Thread.Sleep(100);
    }
    
    // ? Wait for polling to stop
    _pollingTask.Wait();
    
    // Then cleanup
    lwip_cleanup_stack_global();
}
```

---

## ?? What Each Function Does

### `lwip_init_stack_global()`
- Initializes lwIP critical section
- Calls `lwip_init()` (core initialization)
- Sets default netif to NULL
- **Call**: Once at startup

### `lwip_cleanup_stack_global()`
- Closes all active connections
- Removes all network interfaces
- Frees all ACK queues
- Deletes critical section
- Marks as not initialized
- **Call**: Once at shutdown

### `lwip_ssl_init_global()`
- Initializes BoringSSL library
- Creates SSL critical section
- **Call**: Once if using SSL

### `lwip_ssl_cleanup_global()`
- Closes all SSL connections
- Frees all SSL contexts
- Deletes SSL critical section
- **Call**: Once before lwIP cleanup

---

## ? Checklist

### Startup
- [ ] Call `lwip_init_stack_global()`
- [ ] Call `lwip_ssl_init_global()` (if using SSL)
- [ ] Start polling thread (`lwip_poll()` every 10ms)

### Shutdown
- [ ] Stop accepting new work
- [ ] Optional: Wait for pending ACKs (max 5-10s)
- [ ] ? **Stop polling thread** (set flag and wait for exit)
- [ ] Call `lwip_ssl_cleanup_global()` (if using SSL)
- [ ] Call `lwip_cleanup_stack_global()`
- [ ] Stop polling thread

---

## ?? Common Mistakes

### ? Forgot to stop polling before cleanup
```csharp
lwip_cleanup_stack_global();  // ? Polling still running!
// Result: CRASH!
```

### ? Didn't wait for polling thread to exit
```csharp
_running = false;
lwip_cleanup_stack_global();  // ? Thread might still be polling!
// Result: Race condition, possible crash
```

### ? Forgot to cleanup
```csharp
lwip_init_stack_global();
// ... use it ...
// Missing: Stop polling and cleanup
// Result: Memory leaks!
```

### ? Wrong cleanup order
```csharp
_running = false;
await _pollingTask;
lwip_cleanup_stack_global();    // ? Wrong order
lwip_ssl_cleanup_global();
// Result: SSL resources not freed properly
```

### ? Initialize twice
```csharp
lwip_init_stack_global();
lwip_init_stack_global();  // ? Already initialized
```

### ? Use after cleanup
```csharp
_running = false;
await _pollingTask;
lwip_cleanup_stack_global();
lwip_tcp_send(...);  // ? Can't use after cleanup
```

### ? Multiple polling threads
```csharp
Task.Run(() => { while(true) lwip_poll(); });
Task.Run(() => { while(true) lwip_poll(); });  // ? Not thread-safe!
```

---

## ? Correct Examples

### Example 1: Basic with Polling
```csharp
bool _running = true;
Task _pollingTask;

try {
    lwip_init_stack_global();
    
    // Start polling
    _pollingTask = Task.Run(() => {
        while (_running) {
            lwip_poll();
            Thread.Sleep(10);
        }
    });
    
    DoWork();
} finally {
    // Stop polling FIRST
    _running = false;
    _pollingTask.Wait();
    
    // Then cleanup
    lwip_cleanup_stack_global();
}
```

### Example 2: With SSL and Polling
```csharp
bool _running = true;
Task _pollingTask;

try {
    lwip_init_stack_global();
    lwip_ssl_init_global();
    
    // Start polling
    _pollingTask = Task.Run(() => {
        while (_running) {
            lwip_poll();
            Thread.Sleep(10);
        }
    });
    
    DoWork();
} finally {
    // Stop polling FIRST
    _running = false;
    _pollingTask.Wait();
    
    // Then cleanup
    lwip_ssl_cleanup_global();
    lwip_cleanup_stack_global();
}
```

### Example 3: With ACK Wait and Polling
```csharp
bool _running = true;
Task _pollingTask;

try {
    lwip_init_stack_global();
    
    _pollingTask = Task.Run(() => {
        while (_running) {
            lwip_poll();
            Thread.Sleep(10);
        }
    });
    
    DoWork();
    
    // Wait for ACKs (polling still running)
    WaitForAllAcks(TimeSpan.FromSeconds(5));
} finally {
    // Stop polling
    _running = false;
    _pollingTask.Wait();
    
    // Cleanup
    lwip_cleanup_stack_global();
}
```

---

## ?? Quick Decision Tree

```
Is your application closing?
?? YES ? Follow shutdown sequence:
?         1. Stop polling thread (_running = false)
?         2. Wait for polling to exit (await _pollingTask)
?         3. Cleanup SSL (if using): lwip_ssl_cleanup_global()
?         4. Cleanup lwIP: lwip_cleanup_stack_global()
?         ?? Done!
?
?? NO ? Keep using lwIP
        ?? Ensure polling thread is running
            ?? Call lwip_poll() every 10ms
```

---

## ?? Critical Warning

**NEVER call cleanup while polling is still running!**

```csharp
// ? CRASH GUARANTEED!
while (_running) { lwip_poll(); }  // Thread 1
lwip_cleanup_stack_global();        // Thread 2 - CRASH!

# ? SAFE
_running = false;           // Signal stop
await _pollingTask;         // Wait for Thread 1 to exit
lwip_cleanup_stack_global(); // Now safe
