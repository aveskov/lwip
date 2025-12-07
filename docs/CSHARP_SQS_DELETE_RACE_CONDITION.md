# C# Application: SQS Delete Race Condition Fix

## Problem Report

**Issue**: When sending 10 messages, TCP ACK callbacks fire 10 times, but only 8 SQS messages are deleted.

**Root Cause**: Async SQS delete operations are cancelled when service shuts down before they complete.

---

## Log Evidence

### First Batch (10 messages sent)

```
[13:13:48] Message 1 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:48] Message 2 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:48] Message 3 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:48] Message 4 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:48] Message 5 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:48] Message 6 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:49] Message 7 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:49] Message 8 sent ? ACK received ? ? "Deleted acknowledged message"
[13:13:49] Message 9 sent ? ACK received ? ? NO "Deleted acknowledged message"
[13:13:49] Message 10 sent ? ACK received ? ? NO "Deleted acknowledged message"
[13:14:35] Shutting down service
```

### What Happened

1. ? All 10 TCP ACK callbacks fired correctly
2. ? C# started 10 async SQS delete operations
3. ?? Messages 9 & 10 deletes were **still pending**
4. ?? Service shutdown **cancelled** pending Tasks
5. ? SQS messages 9 & 10 remain in queue

---

## Root Cause: Fire-and-Forget Async

### Current Implementation (Broken)

```csharp
// ? BROKEN: Fire-and-forget async
private void OnSslAckComplete(string messageId)
{
    // Decode receipt handle from message_id
    string receiptHandle = DecodeReceiptHandle(messageId);
    
    // This returns immediately, doesn't wait for completion
    _ = DeleteMessageAsync(receiptHandle);  // Fire-and-forget
}

private async Task DeleteMessageAsync(string receiptHandle)
{
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
    }
}
```

### Why It Fails

```
Time  Event
----  -----
T+0   Message 9 ACK arrives ? OnSslAckComplete() called
T+1   DeleteMessageAsync() starts ? Returns Task (not awaited)
T+2   Message 10 ACK arrives ? OnSslAckComplete() called
T+3   DeleteMessageAsync() starts ? Returns Task (not awaited)
T+4   Service shutdown begins
T+5   Tasks 9 & 10 are cancelled (incomplete)
      ? Messages 9 & 10 remain in SQS
```

---

## Solution 1: Track Pending Deletes (Recommended)

### Implementation

```csharp
public class SqsMessageProcessor
{
    private readonly ConcurrentBag<Task> _pendingDeletes = new();
    private readonly SemaphoreSlim _deleteSemaphore = new(10, 10); // Max 10 concurrent deletes
    
    // ACK callback from C++ (called from unmanaged thread)
    private void OnSslAckComplete(string messageId)
    {
        // Decode receipt handle
        string receiptHandle = DecodeReceiptHandle(messageId);
        
        // Start delete and track it
        var deleteTask = DeleteMessageWithTrackingAsync(receiptHandle);
        _pendingDeletes.Add(deleteTask);
    }
    
    private async Task DeleteMessageWithTrackingAsync(string receiptHandle)
    {
        // Limit concurrent deletes
        await _deleteSemaphore.WaitAsync();
        
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
        }
        finally
        {
            _deleteSemaphore.Release();
        }
    }
    
    // Call this during service shutdown
    public async Task WaitForPendingDeletesAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Waiting for {Count} pending SQS deletes...", _pendingDeletes.Count);
        
        try
        {
            // Wait for all deletes with timeout
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10)); // 10 second timeout
            
            await Task.WhenAll(_pendingDeletes).WaitAsync(cts.Token);
            
            _logger.LogInformation("All pending deletes completed successfully");
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Pending deletes cancelled or timed out");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error waiting for pending deletes");
        }
        finally
        {
            _pendingDeletes.Clear();
        }
    }
}
```

### Shutdown Code

```csharp
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    try
    {
        // ... process messages ...
    }
    finally
    {
        _logger.LogInformation("Shutting down service - cleaning up resources");
        
        // ? CRITICAL: Wait for pending deletes before closing SSL
        await _processor.WaitForPendingDeletesAsync(stoppingToken);
        
        // Now safe to disconnect SSL
        _sslConnection?.Disconnect();
    }
}
```

---

## Solution 2: Synchronous Blocking (Simple but Not Recommended)

### Implementation

```csharp
// ?? WARNING: Blocks the ACK callback thread!
private void OnSslAckComplete(string messageId)
{
    string receiptHandle = DecodeReceiptHandle(messageId);
    
    // Block until delete completes
    DeleteMessageAsync(receiptHandle).GetAwaiter().GetResult();
}
```

### Why This Works But Is Not Recommended

? **Pros**:
- Simple
- Guarantees delete completes before callback returns

? **Cons**:
- Blocks unmanaged thread (C++ callback thread)
- Can cause deadlocks if lwIP lock is held
- Slows down ACK processing

---

## Solution 3: Channel-Based Queue (Best for High Throughput)

### Implementation

```csharp
public class SqsMessageProcessor
{
    private readonly Channel<string> _deleteChannel;
    private readonly Task _deleteWorker;
    
    public SqsMessageProcessor()
    {
        _deleteChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
        
        _deleteWorker = Task.Run(ProcessDeleteQueueAsync);
    }
    
    private void OnSslAckComplete(string messageId)
    {
        string receiptHandle = DecodeReceiptHandle(messageId);
        
        // Non-blocking enqueue
        _deleteChannel.Writer.TryWrite(receiptHandle);
    }
    
    private async Task ProcessDeleteQueueAsync()
    {
        await foreach (var receiptHandle in _deleteChannel.Reader.ReadAllAsync())
        {
            try
            {
                await _sqsClient.DeleteMessageAsync(new DeleteMessageRequest
                {
                    QueueUrl = _queueUrl,
                    ReceiptHandle = receiptHandle
                });
                
                _logger.LogInformation("Deleted acknowledged message");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete SQS message");
            }
        }
    }
    
    public async Task ShutdownAsync()
    {
        _logger.LogInformation("Shutting down delete worker...");
        
        // Signal completion
        _deleteChannel.Writer.Complete();
        
        // Wait for worker to finish pending deletes
        await _deleteWorker;
        
        _logger.LogInformation("Delete worker shutdown complete");
    }
}
```

---

## Comparison

| Solution | Complexity | Performance | Reliability | Recommendation |
|----------|-----------|-------------|-------------|----------------|
| **1. Track Pending** | Medium | ???? | ????? | ? **Best for most cases** |
| **2. Blocking** | Low | ?? | ???? | ?? Only for low-volume |
| **3. Channel** | High | ????? | ????? | ? Best for high-volume |

---

## Testing

### Verification Steps

1. **Add delete counter**:
```csharp
private int _deleteCount = 0;

private async Task DeleteMessageAsync(string receiptHandle)
{
    await _sqsClient.DeleteMessageAsync(...);
    Interlocked.Increment(ref _deleteCount);
    _logger.LogInformation("Delete #{Count} completed", _deleteCount);
}
```

2. **Send 10 messages**
3. **Shutdown immediately**
4. **Verify logs**:
```
? Expected: "Delete #1 completed" through "Delete #10 completed"
? Before fix: Only "Delete #1" through "Delete #8"
```

### Load Test

```csharp
// Send 100 messages rapidly
for (int i = 0; i < 100; i++)
{
    await SendMessageAsync(...);
}

// Shutdown immediately
await ShutdownAsync();

// Verify: All 100 messages deleted from SQS
```

---

## Summary

| Aspect | Details |
|--------|---------|
| **Problem** | SQS messages not deleted when service shuts down quickly |
| **Root Cause** | Fire-and-forget async deletes cancelled on shutdown |
| **Fix** | Track pending delete Tasks and await them before shutdown |
| **Impact** | ? 100% SQS message cleanup |
| **Recommended Solution** | Track pending deletes (Solution 1) |
| **Alternative** | Channel-based queue for high throughput (Solution 3) |

---

## Implementation Priority

1. **Immediate**: Implement Solution 1 (Track Pending Deletes)
2. **Optional**: Add delete counter for monitoring
3. **Future**: Migrate to Solution 3 if message volume exceeds 1000/sec

---

**Status**: ? **ISSUE IDENTIFIED - FIX READY**

**Action Required**: Update C# application code to await pending deletes during shutdown.
