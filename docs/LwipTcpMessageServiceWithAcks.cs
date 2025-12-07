using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace Workplace.ActivityDistributionService.Agent.Services.Lwip;

/// <summary>
/// Enhanced LwIP TCP message service with message ID tracking and ACK callbacks
/// </summary>
public class LwipTcpMessageServiceWithAcks : LwipMessageServiceBase
{
    private const double EstablishConnectionTimeout = 5;
    private const int TcpMaximumSegmentSize = 1460;
    private const int MaxPendingMessages = 10000;

    private readonly ILogger<LwipTcpMessageServiceWithAcks> _logger;
    private bool _isTcpConnected;
    
    // Message tracking
    private long _nextMessageNumber = 0;
    private readonly ConcurrentDictionary<string, MessageTrackingInfo> _pendingMessages = new();
    
    public LwipTcpMessageServiceWithAcks(
        IWireGuardContext context, 
        ILogger<LwipTcpMessageServiceWithAcks> logger) : base(context, logger)
    {
        _logger = logger;
        
        // Create lwIP connection
        LwipNative.lwip_create_connection(
            ConnectionId, 
            Context.LocalInsideIp, 
            Netmask, 
            Gateway,
            Delegates.SendCallback, 
            Delegates.CompleteCallback);
    }

    public override async Task SendAsync(string hostName, int port, string message)
    {
        var sendCompletionSource = new TaskCompletionSource();
        Exception? caughtException = null;
        Task? receiveTask = null;

        using var cts = new CancellationTokenSource();

        try
        {
            Delegates.SendCompletionSource = sendCompletionSource;
            Delegates.IsActive = true;

            await EstablishTcpConnectionIfNeeded(hostName, port, cts.Token)
                .WaitAsync(TimeSpan.FromSeconds(EstablishConnectionTimeout), cts.Token);

            receiveTask = ReceiveLoop(ConnectionId, cts.Token);

            var messageId = await SendTcpPersistentWithId(message, cts.Token);

            await Task.WhenAll(sendCompletionSource.Task)
                .WaitAsync(TimeSpan.FromSeconds(SendTimeout), cts.Token);
            
            _logger.LogInformation(
                "Message {MessageId} sent successfully", 
                messageId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during TCP send for connection {ConnectionId}", ConnectionId);
            caughtException = ex;
        }
        finally
        {
            Delegates.IsActive = false;

            if (receiveTask != null)
            {
                try
                {
                    await cts.CancelAsync();
                    await receiveTask;
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Exception while completing receive loop");
                }
            }

            Delegates.SendCompletionSource = null;

            if (caughtException != null)
            {
                throw caughtException;
            }
        }
    }

    private async Task EstablishTcpConnectionIfNeeded(
        string hostName, 
        int port, 
        CancellationToken cancellationToken)
    {
        if (_isTcpConnected || Disposed)
        {
            return;
        }

        var address = GetIpAddress(hostName);
        if (address == null)
        {
            throw new InvalidOperationException($"Could not resolve hostname: {hostName}");
        }

        // ? NEW: Set ACK callback when establishing connection
        LwipNative.lwip_tcp_connect_persistent(
            ConnectionId, 
            address.ToString(), 
            port,
            OnMessageAcknowledged);  // ACK callback set here!

        var availableSize = LwipNative.lwip_tcp_get_send_buffer_available(ConnectionId);
        while (availableSize <= TcpMaximumSegmentSize && 
               !cancellationToken.IsCancellationRequested && 
               !Disposed)
        {
            await Task.Delay(10, cancellationToken);
            availableSize = LwipNative.lwip_tcp_get_send_buffer_available(ConnectionId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        _isTcpConnected = true;
    }

    private async Task<string> SendTcpPersistentWithId(
        string message, 
        CancellationToken cancellationToken)
    {
        // Check pending message limit
        if (_pendingMessages.Count >= MaxPendingMessages)
        {
            throw new InvalidOperationException(
                $"Too many pending messages: {_pendingMessages.Count}");
        }

        var messageBytes = Encoding.UTF8.GetBytes(message);
        
        // Generate unique message ID
        var messageId = GenerateMessageId();
        
        // Track message
        var trackingInfo = new MessageTrackingInfo
        {
            MessageId = messageId,
            SentTime = DateTime.UtcNow,
            MessageSize = messageBytes.Length,
            Status = MessageStatus.Pending
        };
        _pendingMessages[messageId] = trackingInfo;

        // Wait for buffer space
        var availableSize = LwipNative.lwip_tcp_get_send_buffer_available(ConnectionId);
        while (availableSize < TcpMaximumSegmentSize && 
               !cancellationToken.IsCancellationRequested && 
               !Disposed)
        {
            await Task.Delay(30, cancellationToken);
            availableSize = LwipNative.lwip_tcp_get_send_buffer_available(ConnectionId);
        }

        cancellationToken.ThrowIfCancellationRequested();

        // ? NEW: Send with message ID (message_id is now mandatory)
        var result = LwipNative.lwip_tcp_send_persistent(
            ConnectionId, 
            messageBytes, 
            messageBytes.Length,
            messageId);
        
        while (result == -2 && !cancellationToken.IsCancellationRequested && !Disposed)
        {
            await Task.Delay(10, cancellationToken);
            result = LwipNative.lwip_tcp_send_persistent(
                ConnectionId, 
                messageBytes, 
                messageBytes.Length,
                messageId);
        }

        if (result == 0)
        {
            trackingInfo.Status = MessageStatus.Sent;
            _logger.LogDebug(
                "Message {MessageId} sent to TCP buffer ({Bytes} bytes)", 
                messageId, 
                messageBytes.Length);
        }
        else
        {
            trackingInfo.Status = MessageStatus.Failed;
            _pendingMessages.TryRemove(messageId, out _);
            throw new IOException($"TCP send failed with error: {result}");
        }

        return messageId;
    }

    private string GenerateMessageId()
    {
        // Option 1: Sequential with timestamp
        var number = Interlocked.Increment(ref _nextMessageNumber);
        return $"msg_{DateTime.UtcNow:yyyyMMddHHmmssfff}_{number:D6}";
        
        // Option 2: GUID (uncomment to use)
        // return Guid.NewGuid().ToString();
        
        // Option 3: Business-oriented
        // return $"order_{OrderId}_item_{ItemId}_seq_{number}";
    }

    private void OnMessageAcknowledged(string messageId)
    {
        if (_pendingMessages.TryRemove(messageId, out var info))
        {
            info.Status = MessageStatus.Acknowledged;
            info.AckTime = DateTime.UtcNow;
            info.RoundTripTime = info.AckTime.Value - info.SentTime;
            
            _logger.LogInformation(
                "Message {MessageId} acknowledged by server: " +
                "RTT={RTT}ms, Size={Size} bytes, Pending={Pending}",
                messageId,
                info.RoundTripTime.Value.TotalMilliseconds,
                info.MessageSize,
                _pendingMessages.Count);
        }
        else
        {
            _logger.LogWarning(
                "Received ACK for unknown message ID: {MessageId}", 
                messageId);
        }
    }

    /// <summary>
    /// Get statistics about pending messages
    /// </summary>
    public MessageStatistics GetStatistics()
    {
        var messages = _pendingMessages.Values.ToArray();
        var now = DateTime.UtcNow;

        return new MessageStatistics
        {
            TotalPending = messages.Length,
            PendingSent = messages.Count(m => m.Status == MessageStatus.Sent),
            OldestPendingAge = messages.Length > 0 
                ? messages.Max(m => now - m.SentTime) 
                : TimeSpan.Zero,
            AverageAge = messages.Length > 0
                ? TimeSpan.FromMilliseconds(
                    messages.Average(m => (now - m.SentTime).TotalMilliseconds))
                : TimeSpan.Zero
        };
    }

    /// <summary>
    /// Monitor for ACK timeouts (call from background task)
    /// </summary>
    public async Task MonitorAckTimeouts(
        TimeSpan timeout, 
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            var timedOut = _pendingMessages
                .Where(kvp => now - kvp.Value.SentTime > timeout)
                .ToList();

            foreach (var kvp in timedOut)
            {
                _logger.LogWarning(
                    "Message {MessageId} ACK timeout after {Timeout}s",
                    kvp.Key,
                    timeout.TotalSeconds);
                
                if (_pendingMessages.TryRemove(kvp.Key, out var info))
                {
                    info.Status = MessageStatus.Timeout;
                }
            }

            await Task.Delay(1000, cancellationToken);
        }
    }

    public override void Dispose()
    {
        if (Disposed) return;

        // Clear all pending messages
        _pendingMessages.Clear();

        if (_isTcpConnected)
        {
            try
            {
                LwipNative.lwip_tcp_disconnect_persistent(ConnectionId);
                _logger.LogDebug("Disconnected persistent TCP connection {ConnectionId}", ConnectionId);
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Error disconnecting TCP connection {ConnectionId}", ConnectionId);
            }
        }

        try
        {
            LwipNative.lwip_close_connection(ConnectionId);
            _logger.LogDebug("Closed lwIP connection {ConnectionId}", ConnectionId);
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Error closing lwIP connection {ConnectionId}", ConnectionId);
        }

        base.Dispose();
    }
}

public class MessageTrackingInfo
{
    public string MessageId { get; set; }
    public DateTime SentTime { get; set; }
    public DateTime? AckTime { get; set; }
    public TimeSpan? RoundTripTime { get; set; }
    public MessageStatus Status { get; set; }
    public int MessageSize { get; set; }
}

public enum MessageStatus
{
    Pending,
    Sent,
    Acknowledged,
    Timeout,
    Failed
}

public class MessageStatistics
{
    public int TotalPending { get; set; }
    public int PendingSent { get; set; }
    public TimeSpan OldestPendingAge { get; set; }
    public TimeSpan AverageAge { get; set; }
}

/// <summary>
/// P/Invoke declarations for simplified message ID API
/// </summary>
public static class LwipNativeExtensions
{
    /// <summary>
    /// Connect persistent TCP connection with ACK callback
    /// </summary>
    [DllImport("lwip_wrapper", CallingConvention = CallingConvention.Cdecl)]
    public static extern int lwip_tcp_connect_persistent(
        [MarshalAs(UnmanagedType.LPStr)] string id,
        [MarshalAs(UnmanagedType.LPStr)] string destIp,
        int port,
        [MarshalAs(UnmanagedType.FunctionPtr)] SendAckCompleteCallback ackCallback);

    /// <summary>
    /// Send message with mandatory message ID for tracking
    /// </summary>
    [DllImport("lwip_wrapper", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int lwip_tcp_send_persistent(
        [MarshalAs(UnmanagedType.LPStr)] string id,
        byte[] data,
        int len,
        [MarshalAs(UnmanagedType.LPStr)] string messageId);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public delegate void SendAckCompleteCallback([MarshalAs(UnmanagedType.LPStr)] string messageId);
}
