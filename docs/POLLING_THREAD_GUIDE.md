# Polling Thread Management Guide

## Overview

**lwIP requires regular polling** to process timers, retransmissions, and keep-alive probes. The polling thread is **critical** for lwIP operation but **must be managed carefully** during shutdown.

---

## ?? What is Polling?

```c
void lwip_poll(void);
```

This function processes:
- ? TCP retransmissions
- ? TCP timeouts
- ? TCP keep-alive probes
- ? Delayed ACKs
- ? ARP cache updates
- ? Send buffer management

**Must be called every 10-100ms** for proper lwIP operation.

---

## ?? Correct Polling Pattern

### Complete Lifecycle

```
Application Start
    ?
Initialize lwIP
    ?
? START polling thread
    ?
Use lwIP (send/receive)
    ?
? STOP polling thread (signal + wait)
    ?
Cleanup lwIP
    ?
Application Exit
```

---

## ?? C# Implementation Examples

### Example 1: Basic Console Application

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern void lwip_poll();

public class PollingExample
{
    private static bool _running = true;
    private static Task _pollingTask;
    
    public static async Task Main(string[] args)
    {
        Console.CancelKeyPress += (s, e) => {
            e.Cancel = true;
            _running = false;
        };
        
        try
        {
            // 1. Initialize lwIP
            lwip_init_stack_global();
            
            // 2. ? Start polling thread
            Console.WriteLine("Starting polling thread...");
            _pollingTask = Task.Run(PollLoop);
            
            // 3. Use lwIP
            await DoWork();
        }
        finally
        {
            // 4. ? Stop polling thread FIRST
            Console.WriteLine("Stopping polling thread...");
            _running = false;
            
            if (_pollingTask != null)
            {
                await _pollingTask;  // Wait for thread to exit
            }
            Console.WriteLine("Polling stopped");
            
            // 5. Now safe to cleanup
            lwip_cleanup_stack_global();
        }
    }
    
    private static async Task PollLoop()
    {
        Console.WriteLine("Polling thread started (100Hz)");
        
        while (_running)
        {
            lwip_poll();           // Process lwIP timers
            await Task.Delay(10);  // 10ms = 100Hz
        }
        
        Console.WriteLine("Polling thread exited");
    }
}
```

### Example 2: Background Service

```csharp
public class LwipPollingService : BackgroundService
{
    private readonly ILogger<LwipPollingService> _logger;
    
    public LwipPollingService(ILogger<LwipPollingService> logger)
    {
        _logger = logger;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Polling service started");
        
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                lwip_poll();
                await Task.Delay(10, stoppingToken);  // 100Hz
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when stopping
        }
        
        _logger.LogInformation("Polling service stopped");
    }
}

// Startup.cs
services.AddHostedService<LwipPollingService>();
```

### Example 3: Dedicated Polling Thread

```csharp
public class LwipPollingThread : IDisposable
{
    private Thread _thread;
    private volatile bool _running;
    
    public void Start()
    {
        if (_thread != null)
            throw new InvalidOperationException("Already started");
        
        _running = true;
        _thread = new Thread(PollLoop)
        {
            Name = "lwIP Polling",
            IsBackground = true,  // Don't block app shutdown
            Priority = ThreadPriority.Normal
        };
        
        _thread.Start();
        Console.WriteLine("Polling thread started");
    }
    
    public void Stop()
    {
        if (_thread == null)
            return;
        
        Console.WriteLine("Stopping polling thread...");
        _running = false;
        _thread.Join(TimeSpan.FromSeconds(1));  // Wait max 1 second
        
        if (_thread.IsAlive)
        {
            Console.WriteLine("WARNING: Polling thread didn't stop gracefully");
            _thread.Interrupt();  // Force stop
        }
        
        _thread = null;
        Console.WriteLine("Polling thread stopped");
    }
    
    private void PollLoop()
    {
        while (_running)
        {
            try
            {
                lwip_poll();
                Thread.Sleep(10);  // 100Hz
            }
            catch (ThreadInterruptedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Polling error: {ex}");
            }
        }
    }
    
    public void Dispose()
    {
        Stop();
    }
}

// Usage
using (var polling = new LwipPollingThread())
{
    polling.Start();
    
    // Use lwIP...
    
}  // Automatically stops polling
```

### Example 4: High-Performance Timer

```csharp
public class HighPrecisionPolling : IDisposable
{
    private System.Threading.Timer _timer;
    private int _isPolling = 0;  // Atomic flag to prevent overlaps
    
    public void Start()
    {
        // High-precision timer (more accurate than Task.Delay)
        _timer = new System.Threading.Timer(
            callback: OnTimer,
            state: null,
            dueTime: TimeSpan.FromMilliseconds(10),
            period: TimeSpan.FromMilliseconds(10)  // 100Hz
        );
        
        Console.WriteLine("High-precision polling started");
    }
    
    private void OnTimer(object state)
    {
        // Prevent overlapping calls if lwip_poll() takes too long
        if (Interlocked.CompareExchange(ref _isPolling, 1, 0) == 0)
        {
            try
            {
                lwip_poll();
            }
            finally
            {
                Interlocked.Exchange(ref _isPolling, 0);
            }
        }
    }
    
    public void Dispose()
    {
        _timer?.Dispose();
        
        // Wait for any in-progress poll to complete
        SpinWait.SpinUntil(() => _isPolling == 0, TimeSpan.FromSeconds(1));
        
        Console.WriteLine("High-precision polling stopped");
    }
}
```

---

## ?? Polling Frequency Guide

| Frequency | Period | Use Case |
|-----------|--------|----------|
| **50Hz** | 20ms | Low-priority, low CPU |
| **100Hz** | 10ms | **Recommended** - balanced |
| **200Hz** | 5ms | High-performance, low latency |
| **1000Hz** | 1ms | Real-time, very low latency (high CPU) |

### Choosing Frequency

```csharp
// Low latency (recommended)
while (_running) {
    lwip_poll();
    await Task.Delay(10);  // 100Hz
}

// Lower CPU usage
while (_running) {
    lwip_poll();
    await Task.Delay(20);  // 50Hz
}

// Ultra-low latency
while (_running) {
    lwip_poll();
    await Task.Delay(5);   // 200Hz
}
```

---

## ?? Critical: Shutdown Sequence

### ? CORRECT Shutdown

```csharp
// Step 1: Signal polling to stop
_running = false;

// Step 2: Wait for polling thread to exit
await _pollingTask;

// Step 3: Now safe to cleanup
lwip_cleanup_stack_global();
```

**Order is critical!** Cleanup MUST happen after polling stops.

### ? WRONG: Cleanup While Polling

```csharp
// ? CRASH GUARANTEED!
lwip_cleanup_stack_global();  // Frees memory
// ... polling thread still running ...
lwip_poll();  // CRASH! Accessing freed memory
```

### ? WRONG: Poll After Cleanup

```csharp
// ? CRASH GUARANTEED!
lwip_cleanup_stack_global();  // Marks as not initialized
lwip_poll();  // CRASH! lwIP not initialized
```

---

## ?? Common Mistakes

### Mistake 1: Forgot to Start Polling

```csharp
lwip_init_stack_global();
// ? Missing: Start polling thread
// Result: Timeouts, retransmissions don't work, keep-alive fails
```

**Fix**:
```csharp
lwip_init_stack_global();
_pollingTask = Task.Run(PollLoop);  // ? Start polling
```

### Mistake 2: Multiple Polling Threads

```csharp
// ? WRONG - Not thread-safe!
Task.Run(() => { while(true) lwip_poll(); });
Task.Run(() => { while(true) lwip_poll(); });
```

**Fix**: Single polling thread only
```csharp
// ? RIGHT - One thread
_pollingTask = Task.Run(PollLoop);
```

### Mistake 3: Didn't Wait for Thread Exit

```csharp
// ? WRONG - Race condition
_running = false;
lwip_cleanup_stack_global();  // Might still be polling!
```

**Fix**: Wait for thread
```csharp
// ? RIGHT
_running = false;
await _pollingTask;           // Wait for exit
lwip_cleanup_stack_global();
```

### Mistake 4: Polling Too Slow

```csharp
// ? TOO SLOW - Timeouts will occur
while (_running) {
    lwip_poll();
    Thread.Sleep(1000);  // 1 second = 1Hz!
}
```

**Fix**: Poll frequently
```csharp
// ? RIGHT - 100Hz
while (_running) {
    lwip_poll();
    Thread.Sleep(10);
}
```

### Mistake 5: Polling in Multiple Places

```csharp
// ? WRONG - Inconsistent polling
void SendMessage() {
    lwip_tcp_send(...);
    lwip_poll();  // Ad-hoc polling
}

void ReceiveMessage() {
    lwip_poll();  // Ad-hoc polling
}
```

**Fix**: Dedicated polling thread
```csharp
// ? RIGHT - Centralized polling
Task.Run(() => {
    while (_running) {
        lwip_poll();
        Thread.Sleep(10);
    }
});
```

---

## ?? Monitoring Polling Performance

### Example: Measure Polling Duration

```csharp
private static async Task PollLoopWithMetrics()
{
    var stopwatch = new Stopwatch();
    long totalPolls = 0;
    long maxDuration = 0;
    
    while (_running)
    {
        stopwatch.Restart();
        lwip_poll();
        stopwatch.Stop();
        
        totalPolls++;
        maxDuration = Math.Max(maxDuration, stopwatch.ElapsedMilliseconds);
        
        // Log every 10 seconds
        if (totalPolls % 1000 == 0)
        {
            Console.WriteLine($"Polled {totalPolls} times, max duration: {maxDuration}ms");
        }
        
        await Task.Delay(10);
    }
}
```

### Expected Results

```
? Good: Max duration < 5ms
??  Warning: Max duration 5-10ms (might cause latency)
? Bad: Max duration > 10ms (will cause timeouts)
```

---

## ? Best Practices

### 1. Start Polling Immediately After Init

```csharp
lwip_init_stack_global();
_pollingTask = Task.Run(PollLoop);  // ? Start immediately
```

### 2. Use Dedicated Polling Thread

```csharp
// ? Good - Dedicated thread
_pollingTask = Task.Run(PollLoop);

// ? Bad - Mixed with application logic
while (_running) {
    ProcessMessages();
    lwip_poll();  // Don't mix!
}
```

### 3. Poll at 100Hz (10ms)

```csharp
while (_running) {
    lwip_poll();
    await Task.Delay(10);  // ? 100Hz recommended
}
```

### 4. Stop Polling Before Cleanup

```csharp
_running = false;
await _pollingTask;              // ? Wait for exit
lwip_cleanup_stack_global();
```

### 5. Handle Exceptions in Polling Loop

```csharp
private static async Task PollLoop()
{
    while (_running)
    {
        try
        {
            lwip_poll();
            await Task.Delay(10);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Polling error: {ex}");
            // Continue polling even on error
        }
    }
}
```

---

## ?? Complete Example

```csharp
public class CompletePollingExample
{
    private bool _running = false;
    private Task _pollingTask;
    
    public void Start()
    {
        // 1. Initialize lwIP
        lwip_init_stack_global();
        lwip_ssl_init_global();
        
        // 2. ? Start polling thread
        _running = true;
        _pollingTask = Task.Run(async () =>
        {
            Console.WriteLine("Polling started (100Hz)");
            
            while (_running)
            {
                try
                {
                    lwip_poll();
                    await Task.Delay(10);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Polling error: {ex}");
                }
            }
            
            Console.WriteLine("Polling stopped");
        });
        
        Console.WriteLine("System started");
    }
    
    public async Task Stop()
    {
        Console.WriteLine("Stopping system...");
        
        // 1. ? Stop polling FIRST
        _running = false;
        
        if (_pollingTask != null)
        {
            await _pollingTask;
        }
        
        Console.WriteLine("Polling stopped");
        
        // 2. Cleanup
        lwip_ssl_cleanup_global();
        lwip_cleanup_stack_global();
        
        Console.WriteLine("System stopped");
    }
}
```

---

## ?? Summary

### Polling Thread Lifecycle

```
1. Initialize lwIP
   ?
2. ? START polling thread (100Hz recommended)
   ?
3. Use lwIP (polling runs in background)
   ?
4. ? STOP polling thread (signal + wait for exit)
   ?
5. Cleanup lwIP
```

### Critical Rules

1. ? **One polling thread** only (not thread-safe)
2. ? **Poll at 100Hz** (10ms interval)
3. ? **Start immediately** after init
4. ? **Stop before cleanup** (signal + wait)
5. ? **Handle exceptions** in polling loop

### What NOT to Do

1. ? Multiple polling threads
2. ? Cleanup while polling
3. ? Poll after cleanup
4. ? Forget to start polling
5. ? Poll too slowly (> 100ms)

**Result**: Reliable lwIP operation with clean shutdown! ??
