# Quick Reference: TCP Keep-Alive Functions

## ?? Quick Start

### Enable Keep-Alive on SSL Connection

```csharp
// After establishing connection
lwip_ssl_set_keepalive(
    "ssl_conn1",  // connection ID
    1,            // enable
    120,          // 2 minutes idle
    30,           // 30 seconds between probes
    3             // 3 probes before timeout
);
```

### Enable Keep-Alive on TCP Connection

```csharp
// After establishing connection
lwip_tcp_set_keepalive(
    "tcp_conn1",  // connection ID
    1,            // enable
    90,           // 90 seconds idle (firewall-friendly)
    30,           // 30 seconds between probes
    3             // 3 probes before timeout
);
```

---

## ?? Function Signatures

### TCP Keep-Alive
```c
int lwip_tcp_set_keepalive(
    const char* id,        // Connection ID
    int enable,            // 1=enable, 0=disable
    int idle_secs,         // Seconds idle before first probe (0=default: 7200s)
    int interval_secs,     // Seconds between probes (0=default: 75s)
    int count              // Number of probes (0=default: 9)
);
```

### SSL Keep-Alive
```c
int lwip_ssl_set_keepalive(
    const char* id,        // Connection ID
    int enable,            // 1=enable, 0=disable
    int idle_secs,         // Seconds idle before first probe (0=default: 120s)
    int interval_secs,     // Seconds between probes (0=default: 30s)
    int count              // Number of probes (0=default: 3)
);
```

**Returns:**
- `0` = Success
- `-1` = Error (connection not found or invalid state)

---

## ?? Recommended Settings

| Connection Type | Idle | Interval | Count | Use Case |
|----------------|------|----------|-------|----------|
| **SSL Default** | 120s | 30s | 3 | Standard SSL (3.5 min total) |
| **TCP Firewall-Friendly** | 90s | 30s | 3 | Under 5-min firewall timeout |
| **Aggressive** | 60s | 15s | 5 | Quick failure detection |
| **Conservative** | 300s | 60s | 3 | Low overhead |

---

## ? Complete Example

```csharp
public class PersistentSslSender
{
    private string _connectionId = "ssl_persistent";
    
    public async Task Initialize()
    {
        // 1. Create base connection
        lwip_create_connection(
            _connectionId,
            "10.0.0.1",
            "255.255.255.0",
            "10.0.0.254",
            UdpCallback,
            null
        );
        
        // 2. Connect SSL persistent
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
        
        // 3. Wait for handshake
        await WaitForHandshake();
        
        // 4. ? Enable keep-alive
        int result = lwip_ssl_set_keepalive(
            _connectionId,
            1,      // enable
            120,    // 2 minutes idle
            30,     // 30 seconds interval
            3       // 3 probes
        );
        
        if (result != 0)
        {
            throw new Exception("Failed to enable keep-alive");
        }
        
        Console.WriteLine("? Keep-alive enabled - connection will stay alive!");
    }
    
    public void Cleanup()
    {
        // Disable keep-alive before closing
        lwip_ssl_set_keepalive(_connectionId, 0, 0, 0, 0);
        
        // Close connection
        lwip_ssl_disconnect_persistent(_connectionId);
        lwip_close_connection(_connectionId);
    }
}
```

---

## ?? DllImport Declarations

```csharp
[DllImport("lwip_wrapper.dll")]
private static extern int lwip_tcp_set_keepalive(
    string id,
    int enable,
    int idle_secs,
    int interval_secs,
    int count
);

[DllImport("lwip_wrapper.dll")]
private static extern int lwip_ssl_set_keepalive(
    string id,
    int enable,
    int idle_secs,
    int interval_secs,
    int count
);
```

---

## ?? Configuration Required

In `config/lwipopts.h`:
```c
#define LWIP_TCP_KEEPALIVE    1  // Must be enabled!
```

---

## ?? When to Use

? **Use keep-alive when:**
- Connection must stay alive for hours/days
- Behind firewall/NAT that drops idle connections
- Need to detect broken connections quickly
- Using persistent SSL/TCP connections

? **Don't need keep-alive when:**
- Short-lived connections (< 5 minutes)
- Non-persistent connections (single send/close)
- UDP connections (connectionless)

---

## ?? Common Issues

### Issue: Connection still times out

**Fix**: Reduce idle time below firewall timeout
```csharp
// If firewall timeout is 3 minutes
lwip_ssl_set_keepalive(id, 1, 90, 30, 3);  // Under 3 min
```

### Issue: Keep-alive not working

**Check 1**: Is `lwip_poll()` being called?
```csharp
while (true) {
    lwip_poll();  // ? Must be called regularly!
    Thread.Sleep(10);
}
```

**Check 2**: Is `LWIP_TCP_KEEPALIVE` enabled?
```c
// In lwipopts.h
#define LWIP_TCP_KEEPALIVE 1
```

---

## ?? How It Works

```
Connection idle for 120 seconds
        ?
Send keep-alive probe #1
        ?
Wait 30 seconds
        ?
No response? Send probe #2
        ?
Wait 30 seconds
        ?
No response? Send probe #3
        ?
Wait 30 seconds
        ?
No response? Declare connection dead
        ?
Call on_tcp_error() with ERR_TIMEOUT
```

**Total detection time**: `idle + (interval × count)`
- Example: `120s + (30s × 3) = 210s = 3.5 minutes`

---

## ?? Pro Tips

1. **Enable after handshake**
```csharp
await WaitForHandshake();
lwip_ssl_set_keepalive(id, 1, 120, 30, 3);  // ?
```

2. **Use shorter intervals for SSL**
```csharp
lwip_ssl_set_keepalive(id, 1, 120, 30, 3);   // ? SSL
lwip_tcp_set_keepalive(id, 1, 90, 30, 3);    // ? TCP
```

3. **Disable before closing**
```csharp
lwip_ssl_set_keepalive(id, 0, 0, 0, 0);
lwip_ssl_disconnect_persistent(id);
```

4. **Monitor for errors**
```csharp
private void OnTcpError(int errorCode) {
    if (errorCode == ERR_TIMEOUT) {
        Console.WriteLine("Keep-alive detected dead connection");
        Reconnect();
    }
}
```

---

## ? Success Criteria

After enabling keep-alive, your connection should:
- ? Stay alive for hours/days without timing out
- ? Survive firewall/NAT idle timeouts
- ? Detect broken connections within configured time
- ? Work through load balancers and proxies

---

**Full documentation**: See `docs/TCP_KEEPALIVE_GUIDE.md`
