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
1. // Optional: Wait for pending ACKs
2. lwip_ssl_cleanup_global();     // Cleanup SSL first
3. lwip_cleanup_stack_global();   // Cleanup lwIP last
```

### Startup (No SSL)
```csharp
1. lwip_init_stack_global();      // Initialize lwIP
2. // Create connections and use...
```

### Shutdown (No SSL)
```csharp
1. // Optional: Wait for pending ACKs
2. lwip_cleanup_stack_global();   // Cleanup lwIP
```

---

## ?? Common Patterns

### Pattern 1: Console Application
```csharp
static void Main()
{
    try {
        lwip_init_stack_global();
        DoWork();
    } finally {
        lwip_cleanup_stack_global();
    }
}
```

### Pattern 2: IDisposable
```csharp
public class LwipManager : IDisposable
{
    public LwipManager()
    {
        lwip_init_stack_global();
    }
    
    public void Dispose()
    {
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
    public Task StartAsync(CancellationToken ct)
    {
        lwip_init_stack_global();
        return Task.CompletedTask;
    }
    
    public Task StopAsync(CancellationToken ct)
    {
        lwip_cleanup_stack_global();
        return Task.CompletedTask;
    }
}
```

### Pattern 4: Ctrl+C Handler
```csharp
static void Main()
{
    Console.CancelKeyPress += (s, e) => {
        e.Cancel = true;
        lwip_cleanup_stack_global();
        Environment.Exit(0);
    };
    
    lwip_init_stack_global();
    while (true) {
        lwip_poll();
        Thread.Sleep(10);
    }
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
- [ ] Call `lwip_ssl_cleanup_global()` (if using SSL)
- [ ] Call `lwip_cleanup_stack_global()`
- [ ] Stop polling thread

---

## ?? Common Mistakes

### ? Forgot to cleanup
```csharp
lwip_init_stack_global();
// ... use it ...
// Missing: lwip_cleanup_stack_global();
// Result: Memory leaks!
```

### ? Wrong cleanup order
```csharp
lwip_cleanup_stack_global();    // ? Wrong order
lwip_ssl_cleanup_global();
```

### ? Initialize twice
```csharp
lwip_init_stack_global();
lwip_init_stack_global();  // ? Already initialized
```

### ? Use after cleanup
```csharp
lwip_cleanup_stack_global();
lwip_tcp_send(...);  // ? Can't use after cleanup
```

---

## ? Correct Examples

### Example 1: Basic
```csharp
try {
    lwip_init_stack_global();
    DoWork();
} finally {
    lwip_cleanup_stack_global();
}
```

### Example 2: With SSL
```csharp
try {
    lwip_init_stack_global();
    lwip_ssl_init_global();
    DoWork();
} finally {
    lwip_ssl_cleanup_global();
    lwip_cleanup_stack_global();
}
```

### Example 3: With ACK Wait
```csharp
try {
    lwip_init_stack_global();
    DoWork();
    WaitForAllAcks(TimeSpan.FromSeconds(5));
} finally {
    lwip_cleanup_stack_global();
}
```

---

## ?? Quick Decision Tree

```
Is your application closing?
?? YES ? Call cleanup functions
?         ?? Using SSL?
?         ?  ?? YES ? lwip_ssl_cleanup_global() ? lwip_cleanup_stack_global()
?         ?  ?? NO  ? lwip_cleanup_stack_global()
?         ?? Done!
?
?? NO ? Keep using lwIP
        ?? Call lwip_poll() regularly
```

---

## ?? Success Criteria

After calling cleanup functions:
- ? All connections closed
- ? All memory freed
- ? No resource leaks
- ? Can reinitialize if needed
- ? Application exits cleanly

---

**Full documentation**: See `docs/APPLICATION_LIFECYCLE_GUIDE.md`
