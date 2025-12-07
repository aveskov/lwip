# C# Async Delegate Fix for SSL ACK Callbacks

## Your Current Code (The Problem)

```csharp
protected void OnAckReceived(string messageId)
{
    try
    {
        if (!Delegates.IsActive) return;
    
        Logger.LogDebug("ACK received for messageId {MessageId} on connection {ConnectionId}", 
            messageId, ConnectionId);
        
        DeleteCallback?.Invoke(messageId);  // ? Fire-and-forget!
    }
    catch (Exception ex)
    {
        Logger.LogError(ex, "Error processing ACK for messageId {MessageId}", messageId);
    }
}
```

### What's Wrong

1. `DeleteCallback?.Invoke()` is **synchronous** (no `await`)
2. The delegate likely starts an **async Task** but doesn't wait for it
3. Service shutdown **cancels** pending Tasks before they complete
4. Result: **SQS messages not deleted** (8 out of 10 in your case)

---

## Solution 1: Track Pending Async Operations (Recommended)

### Step 1: Change Delegate Type to Async

```csharp
// OLD (synchronous delegate)
public Action<string>? DeleteCallback { get; set; }

// NEW (async delegate)
public Func<string, Task>? DeleteCallback { get; set; }
```

### Step 2: Track Pending Operations

```csharp
public class SslConnection
{
    private readonly ConcurrentBag<Task> _pendingAcks = new();
    private readonly SemaphoreSlim _ackSemaphore = new(50, 50); // Limit concurrent ops
    
    public Func<string, Task>? DeleteCallback { get; set; }
    
    protected void OnAckReceived(string messageId)
    {
        try
        {
            if (!Delegates.IsActive) return;
        
            Logger.LogDebug("ACK received for messageId {MessageId} on connection {ConnectionId}", 
                messageId, ConnectionId);
            
            // Start and track the async operation
            var deleteTask = ProcessAckAsync(messageId);
            _pendingAcks.Add(deleteTask);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error processing ACK for messageId {MessageId}", messageId);
        }
    }
    
    private async Task ProcessAckAsync(string messageId)
    {
        await _ackSemaphore.WaitAsync();
        
        try
        {
            if (DeleteCallback != null)
            {
                await DeleteCallback(messageId);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error in delete callback for messageId {MessageId}", messageId);
        }
        finally
        {
            _ackSemaphore.Release();
        }
    }
    
    public async Task WaitForPendingAcksAsync(CancellationToken cancellationToken = default)
    {
        Logger.LogInformation("Waiting for {Count} pending ACK operations...", _pendingAcks.Count);
        
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10)); // 10 second timeout
            
            await Task.WhenAll(_pendingAcks).WaitAsync(cts.Token);
            
            Logger.LogInformation("All pending ACK operations completed");
        }
        catch (OperationCanceledException)
        {
            Logger.LogWarning("Pending ACK operations cancelled or timed out");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error waiting for pending ACK operations");
        }
        finally
        {
            _pendingAcks.Clear();
        }
    }
}
```

### Step 3: Update SQS Handler

```csharp
public class SqsToSyslogService
{
    private SslConnection? _sslConnection;
    
    private async Task OnDeleteMessageAsync(string messageId)
    {
        // Decode receipt handle from messageId
        string receiptHandle = DecodeReceiptHandle(messageId);
        
        try
        {
            await _sqsClient.DeleteMessageAsync(new DeleteMessageRequest
            {
                QueueUrl = _queueUrl,
                ReceiptHandle = receiptHandle
            });
            
            _logger.LogInformation("Deleted acknowledged message (receipt: {Receipt})", 
                receiptHandle.Substring(0, 50));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete SQS message");
            throw; // Rethrow so caller knows it failed
        }
    }
    
    private void SetupConnection()
    {
        _sslConnection = new SslConnection(...);
        
        // Set the async delete callback
        _sslConnection.DeleteCallback = OnDeleteMessageAsync;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            SetupConnection();
            
            // ... process messages ...
        }
        finally
        {
            _logger.LogInformation("Shutting down - waiting for pending ACKs");
            
            // ? CRITICAL: Wait for all pending ACKs before closing connection
            if (_sslConnection != null)
            {
                await _sslConnection.WaitForPendingAcksAsync(stoppingToken);
                _sslConnection.Disconnect();
            }
        }
    }
}
```

---

## Solution 2: Blocking Approach (Simpler but Not Recommended)

If you can't change the delegate type to `Func<string, Task>`, you can use blocking:

```csharp
protected void OnAckReceived(string messageId)
{
    try
    {
        if (!Delegates.IsActive) return;
    
        Logger.LogDebug("ACK received for messageId {MessageId} on connection {ConnectionId}", 
            messageId, ConnectionId);
        
        // ?? WARNING: Blocks the callback thread!
        DeleteCallback?.Invoke(messageId);
        
        // If DeleteCallback starts async work, wait for it:
        if (_deleteTask != null)
        {
            _deleteTask.GetAwaiter().GetResult();
        }
    }
    catch (Exception ex)
    {
        Logger.LogError(ex, "Error processing ACK for messageId {MessageId}", messageId);
    }
}
```

### Why This Is Not Recommended

- ? **Blocks the C++ callback thread** (unmanaged code)
- ? **Potential deadlock** if locks are involved
- ? **Slows down ACK processing**
- ? **Not scalable** for high throughput

---

## Solution 3: Channel-Based Queue (Best for High Volume)

For high-throughput scenarios (>100 messages/sec):

```csharp
public class SslConnection
{
    private readonly Channel<string> _ackChannel;
    private readonly Task _ackWorker;
    
    public Func<string, Task>? DeleteCallback { get; set; }
    
    public SslConnection()
    {
        _ackChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });
        
        _ackWorker = Task.Run(ProcessAckQueueAsync);
    }
    
    protected void OnAckReceived(string messageId)
    {
        try
        {
            if (!Delegates.IsActive) return;
        
            Logger.LogDebug("ACK received for messageId {MessageId}", messageId);
            
            // Non-blocking enqueue
            if (!_ackChannel.Writer.TryWrite(messageId))
            {
                Logger.LogWarning("Failed to enqueue ACK for messageId {MessageId}", messageId);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error processing ACK for messageId {MessageId}", messageId);
        }
    }
    
    private async Task ProcessAckQueueAsync()
    {
        await foreach (var messageId in _ackChannel.Reader.ReadAllAsync())
        {
            try
            {
                if (DeleteCallback != null)
                {
                    await DeleteCallback(messageId);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error in delete callback for messageId {MessageId}", messageId);
            }
        }
    }
    
    public async Task ShutdownAsync()
    {
        Logger.LogInformation("Shutting down ACK processor...");
        
        // Signal completion (no more ACKs will be enqueued)
        _ackChannel.Writer.Complete();
        
        // Wait for worker to finish processing pending ACKs
        await _ackWorker;
        
        Logger.LogInformation("ACK processor shutdown complete");
    }
}
```

### Usage with Shutdown

```csharp
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    try
    {
        _sslConnection = new SslConnection(...);
        _sslConnection.DeleteCallback = OnDeleteMessageAsync;
        
        // ... process messages ...
    }
    finally
    {
        _logger.LogInformation("Shutting down service");
        
        // Wait for ACK queue to drain
        if (_sslConnection != null)
        {
            await _sslConnection.ShutdownAsync();
        }
    }
}
```

---

## Comparison

| Solution | Complexity | Performance | Reliability | Best For |
|----------|-----------|-------------|-------------|----------|
| **1. Track Pending** | Medium | ???? | ????? | General use (10-100 msg/sec) |
| **2. Blocking** | Low | ?? | ??? | Very low volume (<10 msg/sec) |
| **3. Channel Queue** | High | ????? | ????? | High volume (>100 msg/sec) |

---

## Testing the Fix

### Add Metrics

```csharp
public class SslConnection
{
    private int _acksReceived = 0;
    private int _acksProcessed = 0;
    
    protected void OnAckReceived(string messageId)
    {
        Interlocked.Increment(ref _acksReceived);
        
        // ... existing code ...
        
        var deleteTask = ProcessAckAsync(messageId);
        _pendingAcks.Add(deleteTask);
    }
    
    private async Task ProcessAckAsync(string messageId)
    {
        try
        {
            // ... existing code ...
            
            Interlocked.Increment(ref _acksProcessed);
            Logger.LogDebug("ACK #{Processed} processed (total received: {Received})", 
                _acksProcessed, _acksReceived);
        }
        finally
        {
            // ... cleanup ...
        }
    }
}
```

### Verify Logs

```
? Expected after fix:
[13:14:35] ACK #1 processed (total received: 10)
[13:14:35] ACK #2 processed (total received: 10)
...
[13:14:35] ACK #10 processed (total received: 10)
[13:14:35] Waiting for 0 pending ACK operations...
[13:14:35] All pending ACK operations completed
[13:14:35] Shutting down service

? Before fix:
[13:14:35] ACK #8 processed (total received: 10)
[13:14:35] Shutting down service (2 ACKs lost!)
```

---

## Summary

### Root Cause
Your `DeleteCallback?.Invoke(messageId)` is **fire-and-forget** - it starts an async operation but doesn't wait for completion.

### Fix
1. Change delegate to `Func<string, Task>` (async)
2. Track pending Tasks in a `ConcurrentBag<Task>`
3. Wait for all pending Tasks during shutdown: `await Task.WhenAll(_pendingAcks)`

### Implementation Priority
1. ? **Immediate**: Implement Solution 1 (Track Pending)
2. ?? **Optional**: Add metrics to verify all ACKs processed
3. ?? **Future**: Migrate to Solution 3 if volume exceeds 100 msg/sec

---

**Status**: ? **SOLUTION READY**

**Estimated Effort**: 1-2 hours to implement Solution 1

**Impact**: Will fix the "8 out of 10 ACKs" issue permanently
