# TCP Keep-Alive Guide - Preventing Persistent Connections from Becoming Stale

## Problem

Persistent TCP and SSL connections become **stale/timeout** after several minutes of inactivity because:

1. **Firewalls** drop idle connections (typically after 2-5 minutes)
2. **NAT routers** clear idle connection mappings
3. **Load balancers** timeout inactive connections
4. **Network issues** go undetected (cable unplugged, server crash)

## Solution: TCP Keep-Alive

TCP keep-alive sends **periodic probe packets** to:
- ? Keep the connection "active" in firewalls/NAT
- ? Detect broken connections early
- ? Prevent timeouts during idle periods

---

## ?? Implementation

### TCP Keep-Alive (Non-SSL)

```c
// Function signature
int lwip_tcp_set_keepalive(const char* id, 
                           int enable, 
                           int idle_secs, 
                           int interval_secs, 
                           int count);
```

**Parameters:**
- `id`: Connection identifier
- `enable`: 1 = enable, 0 = disable
- `idle_secs`: Seconds of inactivity before first probe (0 = use default)
- `interval_secs`: Seconds between probes (0 = use default)
- `count`: Number of probes before giving up (0 = use default)

### SSL Keep-Alive

```c
// Function signature  
int lwip_ssl_set_keepalive(const char* id,
                           int enable,
                           int idle_secs,
                           int interval_secs,
                           int count);
```

---

## ?? C# Usage Examples

### Example 1: Enable Keep-Alive on TCP Connection

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern int lwip_tcp_set_keepalive(
    string id,
    int enable,
    int idle_secs,
    int interval_secs,
    int count
);

public class TcpPersistentSender
{
    private string _connectionId = "tcp_conn1";
    
    public void Initialize()
    {
        // Create base connection
        lwip_create_connection(_connectionId, "10.0.0.1", "255.255.255.0", 
                               "10.0.0.254", UdpCallback, null);
        
        // Connect persistent TCP
        lwip_tcp_connect_persistent(_connectionId, "192.168.1.100", 8080, OnAckComplete);
        
        // ? Enable keep-alive: probe after 60s idle, then every 30s, max 3 probes
        int result = lwip_tcp_set_keepalive(
            _connectionId,
            1,      // enable
            60,     // idle: 60 seconds before first probe
            30,     // interval: 30 seconds between probes
            3       // count: 3 probes before giving up
        );
        
        if (result == 0)
        {
            Console.WriteLine("Keep-alive enabled successfully");
        }
    }
}
```

### Example 2: Enable Keep-Alive on SSL Connection

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern int lwip_ssl_set_keepalive(
    string id,
    int enable,
    int idle_secs,
    int interval_secs,
    int count
);

public class SslPersistentSender
{
    private string _connectionId = "ssl_conn1";
    
    public async Task Initialize()
    {
        // Create base connection
        lwip_create_connection(_connectionId, "10.0.0.1", "255.255.255.0",
                               "10.0.0.254", UdpCallback, null);
        
        // Connect SSL persistent
        lwip_ssl_connect_persistent(
            _connectionId,
            "192.168.1.100",
            443,
            "api.example.com",
            OnHandshakeComplete,
            OnDataReceived,
            OnSendComplete,
            OnAckComplete
        );
        
        // Wait for handshake
        await WaitForHandshake();
        
        // ? Enable keep-alive for SSL (shorter intervals recommended)
        int result = lwip_ssl_set_keepalive(
            _connectionId,
            1,      // enable
            120,    // idle: 2 minutes (SSL default)
            30,     // interval: 30 seconds
            3       // count: 3 probes
        );
        
        if (result == 0)
        {
            Console.WriteLine("SSL keep-alive enabled");
        }
    }
}
```

### Example 3: Default Keep-Alive (Recommended for Most Cases)

```csharp
public void EnableDefaultKeepAlive(string connectionId)
{
    // Use defaults: idle=120s, interval=30s, count=3
    // Pass 0 for parameters to use defaults
    int result = lwip_ssl_set_keepalive(
        connectionId,
        1,    // enable
        0,    // use default idle (120s for SSL, 7200s for TCP)
        0,    // use default interval (30s for SSL, 75s for TCP)
        0     // use default count (3 for SSL, 9 for TCP)
    );
    
    Console.WriteLine($"Keep-alive enabled with defaults: {result == 0}");
}
```

### Example 4: Long-Running Background Service

```csharp
public class BackgroundMessageSender : IHostedService
{
    private string _sslConnectionId = "ssl_background";
    private Timer _heartbeatTimer;
    
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Setup SSL connection
        SetupSslConnection();
        await WaitForHandshake();
        
        // ? Enable aggressive keep-alive for 24/7 service
        lwip_ssl_set_keepalive(
            _sslConnectionId,
            1,      // enable
            60,     // probe after 1 minute idle
            15,     // every 15 seconds
            5       // 5 attempts (5 * 15s = 75s max detection time)
        );
        
        // Start message processing
        StartMessageProcessing();
    }
    
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // Disable keep-alive before closing
        lwip_ssl_set_keepalive(_sslConnectionId, 0, 0, 0, 0);
        
        // Close connection
        lwip_ssl_disconnect_persistent(_sslConnectionId);
    }
}
```

### Example 5: Firewall-Friendly Configuration

```csharp
public class FirewallFriendlySender
{
    // Many firewalls drop connections after 2-5 minutes
    // Use keep-alive to stay under that threshold
    
    public void SetupConnection(string connectionId)
    {
        lwip_tcp_connect_persistent(connectionId, "192.168.1.100", 8080, null);
        
        // ? Probe every 90 seconds to stay under typical 5-minute timeout
        lwip_tcp_set_keepalive(
            connectionId,
            1,      // enable
            90,     // idle: 90 seconds (under typical firewall timeout)
            30,     // interval: 30 seconds
            3       // count: 3 probes
        );
    }
}
```

---

## ?? Configuration Guide

### Recommended Settings

| Scenario | Idle (seconds) | Interval (seconds) | Count | Total Detection Time |
|----------|----------------|-------------------|-------|---------------------|
| **SSL (default)** | 120 | 30 | 3 | 2 min + 90s = 3.5 min |
| **TCP (default)** | 7200 | 75 | 9 | 2 hours + 11.25 min |
| **Aggressive** | 60 | 15 | 5 | 1 min + 75s = 2.25 min |
| **Firewall-friendly** | 90 | 30 | 3 | 1.5 min + 90s = 3 min |
| **Conservative** | 300 | 60 | 3 | 5 min + 3 min = 8 min |

### How Keep-Alive Works

```
Connection established
        ?
        ? (idle for 120 seconds)
        ?
First keep-alive probe sent ????? ACK received ????? Connection OK
        ?                              ?
        ? (no response)                ? (idle for 120 seconds)
        ?                              ?
        ?                         Next probe cycle...
Wait 30 seconds
        ?
        ?
Second probe sent ????? ACK received ????? Connection OK
        ?                    
        ? (no response)      
        ?                    
Wait 30 seconds
        ?
        ?
Third probe sent ????? ACK received ????? Connection OK
        ?
        ? (no response)
        ?
Connection declared dead
        ?
        ?
on_tcp_error() called
```

### Tuning Guidelines

**Idle Time (`idle_secs`):**
- **Short (60-90s)**: Best for detecting failures quickly, more network overhead
- **Medium (120-300s)**: Balanced - recommended for SSL
- **Long (1800-7200s)**: Less overhead, slower failure detection

**Interval (`interval_secs`):**
- **Short (15-30s)**: Fast detection, more probes
- **Medium (30-60s)**: Balanced
- **Long (60-120s)**: Slower detection, less overhead

**Count (`count`):**
- **Low (3)**: Faster detection (recommended for SSL)
- **Medium (5-7)**: Balanced
- **High (9+)**: More tolerant of network issues

---

## ?? Best Practices

### 1. Enable After Connection Established

```csharp
public async Task SetupSslConnection()
{
    // Connect first
    lwip_ssl_connect_persistent(...);
    
    // Wait for handshake
    await WaitForHandshake();
    
    // ? THEN enable keep-alive
    lwip_ssl_set_keepalive(connectionId, 1, 120, 30, 3);
}
```

### 2. Disable Before Closing

```csharp
public void CloseConnection(string connectionId)
{
    // Disable keep-alive first
    lwip_ssl_set_keepalive(connectionId, 0, 0, 0, 0);
    
    // Then close
    lwip_ssl_disconnect_persistent(connectionId);
}
```

### 3. Use Shorter Intervals for SSL

```csharp
// ? Good for SSL
lwip_ssl_set_keepalive(id, 1, 120, 30, 3);  // Probe every 2 min

// ? Too long for SSL (might timeout anyway)
lwip_ssl_set_keepalive(id, 1, 7200, 75, 9);  // 2 hours!
```

### 4. Poll Regularly

```csharp
// Keep-alive still requires polling
private async Task PollLoop()
{
    while (_running)
    {
        lwip_poll();  // ? Processes keep-alive probes
        await Task.Delay(10);
    }
}
```

### 5. Handle Connection Errors

```csharp
private void OnTcpError(int errorCode)
{
    Console.WriteLine($"Connection error: {errorCode}");
    
    if (errorCode == ERR_TIMEOUT)  // Keep-alive detected dead connection
    {
        Console.WriteLine("Keep-alive detected connection failure - reconnecting...");
        Reconnect();
    }
}
```

---

## ?? Performance Impact

### Network Overhead

| Idle Time | Probes per Hour | Data per Hour |
|-----------|----------------|---------------|
| 60s | 60 | ~3.6 KB |
| 120s | 30 | ~1.8 KB |
| 300s | 12 | ~720 bytes |

**Conclusion**: Network overhead is negligible (< 4 KB/hour)

### CPU Impact

- **Minimal**: Keep-alive processed during `lwip_poll()`
- **No additional threads** required
- **No measurable performance impact**

---

## ?? Troubleshooting

### Problem: Connection Still Times Out

**Solution 1**: Reduce idle time
```csharp
// Change from 120s to 60s
lwip_ssl_set_keepalive(id, 1, 60, 30, 3);
```

**Solution 2**: Check firewall/NAT timeout
```csharp
// If firewall timeout is 3 minutes, use:
lwip_ssl_set_keepalive(id, 1, 90, 30, 2);  // Under 3 minutes
```

### Problem: Keep-Alive Not Working

**Check 1**: Is polling active?
```csharp
// Must call lwip_poll() regularly
while (true) {
    lwip_poll();  // ? Required!
    Thread.Sleep(10);
}
```

**Check 2**: Is keep-alive enabled in config?
```c
// In lwipopts.h
#define LWIP_TCP_KEEPALIVE 1  // ? Must be enabled
```

### Problem: Too Many Keep-Alive Probes

**Solution**: Increase idle time
```csharp
// Change from 60s to 300s
lwip_ssl_set_keepalive(id, 1, 300, 60, 3);
```

---

## ?? Summary

### For SSL Connections (Recommended):
```csharp
lwip_ssl_set_keepalive(id, 1, 120, 30, 3);
// Idle: 2 minutes
// Interval: 30 seconds  
// Count: 3 probes
// Total detection: ~3.5 minutes
```

### For TCP Connections (Firewall-Friendly):
```csharp
lwip_tcp_set_keepalive(id, 1, 90, 30, 3);
// Idle: 90 seconds (under typical 5-min firewall timeout)
// Interval: 30 seconds
// Count: 3 probes
// Total detection: ~3 minutes
```

### Use Default Settings:
```csharp
lwip_ssl_set_keepalive(id, 1, 0, 0, 0);  // SSL defaults
lwip_tcp_set_keepalive(id, 1, 0, 0, 0);  // TCP defaults
```

---

## ? Checklist

- [ ] Enable `LWIP_TCP_KEEPALIVE` in `lwipopts.h`
- [ ] Call `lwip_[ssl/tcp]_set_keepalive()` after connection established
- [ ] Use appropriate idle time (< firewall timeout)
- [ ] Ensure `lwip_poll()` is called regularly
- [ ] Handle connection errors (ERR_TIMEOUT)
- [ ] Disable keep-alive before closing connection

**Result**: Your persistent connections will stay alive indefinitely! ??
