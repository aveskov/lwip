# lwIP Wrapper Documentation

**Welcome to the lwIP Wrapper documentation!**

This directory contains comprehensive documentation for the thread-safe lwIP TCP/IP stack wrapper for Windows.

---

## ?? Documentation Structure

### ? **Start Here**

**[LWIP_WRAPPER_ARCHITECTURE.md](LWIP_WRAPPER_ARCHITECTURE.md)** - **Master Document**
- Complete architecture overview
- Core components and design patterns
- API reference for all functions
- Memory management and threading model
- Protocol support (TCP, UDP, SSL/TLS)
- Performance optimizations
- Best practices and troubleshooting

**Read this first** to understand the entire system!

---

### ?? **Feature-Specific Guides**

#### **[APPLICATION_LIFECYCLE_GUIDE.md](APPLICATION_LIFECYCLE_GUIDE.md)**
- Complete application lifecycle
- Initialization and cleanup sequences
- Shutdown patterns (with examples)
- Polling thread management
- **Use when**: Setting up or tearing down your application

#### **[BATCH_OPTIMIZATION_COMPLETE_GUIDE.md](BATCH_OPTIMIZATION_COMPLETE_GUIDE.md)**
- High-throughput batch sending
- TCP/UDP/SSL batch APIs
- Performance benchmarks
- Configuration tuning
- **Use when**: Optimizing for maximum throughput

#### **[TCP_KEEPALIVE_GUIDE.md](TCP_KEEPALIVE_GUIDE.md)**
- TCP keep-alive configuration
- Preventing connection timeouts
- Firewall-friendly settings
- Troubleshooting idle connections
- **Use when**: Connections timeout after minutes

#### **[ip4_route_custom_documentation.md](ip4_route_custom_documentation.md)**
- Custom IP routing implementation
- Multi-interface routing
- Source-based routing
- **Use when**: Working with multiple network interfaces

---

## ?? Quick Start

### 1. **Understand the Architecture**
Read [LWIP_WRAPPER_ARCHITECTURE.md](LWIP_WRAPPER_ARCHITECTURE.md) sections:
- Overview
- Core Components
- Connection Types

### 2. **Set Up Your Application**
Follow [APPLICATION_LIFECYCLE_GUIDE.md](APPLICATION_LIFECYCLE_GUIDE.md):
- Initialize lwIP stack
- Start polling thread
- Create connections

### 3. **Optimize Performance** (Optional)
Check [BATCH_OPTIMIZATION_COMPLETE_GUIDE.md](BATCH_OPTIMIZATION_COMPLETE_GUIDE.md):
- Use persistent connections
- Enable batch sending
- Tune configuration

### 4. **Prevent Timeouts** (If Needed)
See [TCP_KEEPALIVE_GUIDE.md](TCP_KEEPALIVE_GUIDE.md):
- Enable keep-alive
- Configure intervals
- Handle firewall timeouts

---

## ?? Common Use Cases

### Sending Single TCP Messages
```
1. Read: ARCHITECTURE ? "Non-Persistent TCP"
2. Use: lwip_tcp_send()
```

### High-Throughput TCP Sending
```
1. Read: ARCHITECTURE ? "Persistent TCP"
2. Read: BATCH_OPTIMIZATION ? "TCP Batch"
3. Use: lwip_tcp_connect_persistent() + lwip_tcp_send_batch_optimized()
```

### SSL/TLS Connections
```
1. Read: ARCHITECTURE ? "SSL/TLS Connections"
2. Read: APPLICATION_LIFECYCLE ? "Example 3" (SSL setup)
3. Use: lwip_ssl_connect_persistent() + lwip_ssl_send_persistent()
```

### Long-Running Connections
```
1. Read: ARCHITECTURE ? "TCP Keep-Alive"
2. Read: TCP_KEEPALIVE_GUIDE (detailed config)
3. Use: lwip_tcp_set_keepalive() or lwip_ssl_set_keepalive()
```

### Application Shutdown
```
1. Read: APPLICATION_LIFECYCLE ? "Shutdown Sequence"
2. Follow: Stop polling ? Wait ? Cleanup SSL ? Cleanup lwIP
```

---

## ?? API Quick Reference

### Core Functions

**Initialization**:
- `lwip_init_stack_global()` - Initialize lwIP
- `lwip_ssl_init_global()` - Initialize SSL
- `lwip_poll()` - Process timers (call every 10ms)

**Cleanup**:
- `lwip_cleanup_stack_global()` - Cleanup lwIP
- `lwip_ssl_cleanup_global()` - Cleanup SSL

**Connection Management**:
- `lwip_create_connection()` - Create virtual connection
- `lwip_close_connection()` - Close connection

**TCP Operations**:
- `lwip_tcp_send()` - Single send (non-persistent)
- `lwip_tcp_connect_persistent()` - Persistent connection
- `lwip_tcp_send_persistent()` - Send on persistent connection
- `lwip_tcp_send_batch_optimized()` - Batch send
- `lwip_tcp_disconnect_persistent()` - Close persistent connection

**UDP Operations**:
- `lwip_udp_send()` - Single UDP send
- `lwip_udp_send_batch_optimized()` - Batch UDP send

**SSL Operations**:
- `lwip_ssl_connect_persistent()` - Persistent SSL connection
- `lwip_ssl_send_persistent()` - Send SSL data
- `lwip_ssl_send_batch_optimized()` - Batch SSL send
- `lwip_ssl_disconnect_persistent()` - Close SSL connection

**Utilities**:
- `lwip_tcp_set_keepalive()` - Configure keep-alive
- `lwip_tcp_get_send_buffer_available()` - Check buffer space
- `lwip_tcp_get_pending_ack_count()` - Check pending ACKs

See [LWIP_WRAPPER_ARCHITECTURE.md](LWIP_WRAPPER_ARCHITECTURE.md#11-api-reference) for complete API reference.

---

## ?? Troubleshooting

| Problem | Solution | Reference |
|---------|----------|-----------|
| **Connection timeouts** | Enable keep-alive | [TCP_KEEPALIVE_GUIDE.md](TCP_KEEPALIVE_GUIDE.md) |
| **Buffer full errors** | Retry after poll | [ARCHITECTURE §10](LWIP_WRAPPER_ARCHITECTURE.md#10-error-handling) |
| **Crash on exit** | Stop polling first | [APPLICATION_LIFECYCLE](APPLICATION_LIFECYCLE_GUIDE.md#shutdown-sequence) |
| **Low throughput** | Use batch send | [BATCH_OPTIMIZATION](BATCH_OPTIMIZATION_COMPLETE_GUIDE.md) |
| **Memory leaks** | Check cleanup | [ARCHITECTURE §5](LWIP_WRAPPER_ARCHITECTURE.md#5-memory-management) |
| **ACKs not received** | Check polling | [APPLICATION_LIFECYCLE](APPLICATION_LIFECYCLE_GUIDE.md#polling) |

---

## ?? Performance Guide

### Expected Throughput (300-byte messages)

| Protocol | Mode | Throughput | Use Case |
|----------|------|------------|----------|
| **TCP** | Non-persistent | 50 msg/s | Simple one-time sends |
| **TCP** | Persistent | 1,800 msg/s | Multiple messages |
| **TCP** | Batch (10) | 2,500 msg/s | High throughput |
| **UDP** | Single | 500 msg/s | Best-effort data |
| **UDP** | Batch (20) | 4,500 msg/s | High-volume logs |
| **SSL** | Persistent | 1,200 msg/s | Secure data |
| **SSL** | Batch (10) | 1,600 msg/s | Secure + fast |

See [BATCH_OPTIMIZATION_COMPLETE_GUIDE.md](BATCH_OPTIMIZATION_COMPLETE_GUIDE.md) for detailed benchmarks.

---

## ?? Documentation Updates

**Last Consolidation**: 2024

**Previous Documentation**:
- 51 separate documentation files
- Redundant information across multiple files
- Difficult to find relevant information

**Current Documentation**:
- 5 focused documents (plus README and consolidation plan)
- All information consolidated and organized
- Clear navigation and cross-references

See [DOCUMENTATION_CONSOLIDATION_PLAN.md](DOCUMENTATION_CONSOLIDATION_PLAN.md) for details.

---

## ?? Document Descriptions

### LWIP_WRAPPER_ARCHITECTURE.md
**Size**: Comprehensive (16 sections)  
**Audience**: All developers  
**Content**:
- System architecture and design
- All core components explained
- Complete API reference
- Threading and memory management
- Protocol support details
- Performance optimizations
- Best practices
- Troubleshooting guide

### APPLICATION_LIFECYCLE_GUIDE.md
**Size**: Detailed guide  
**Audience**: Application developers  
**Content**:
- Complete lifecycle examples
- Initialization patterns
- Shutdown sequences (critical!)
- Polling thread management
- IHostedService, IDisposable patterns
- Console app, Windows Service examples
- Common mistakes and solutions

### BATCH_OPTIMIZATION_COMPLETE_GUIDE.md
**Size**: Performance guide  
**Audience**: Performance-focused developers  
**Content**:
- TCP/UDP/SSL batch APIs
- TCP_WRITE_FLAG_MORE optimization
- Performance benchmarks
- Configuration tuning
- C# marshaling examples
- Protocol comparison

### TCP_KEEPALIVE_GUIDE.md
**Size**: Feature-specific guide  
**Audience**: Long-running connection users  
**Content**:
- Keep-alive configuration
- Firewall-friendly settings
- Timeout prevention
- Troubleshooting idle connections
- C# configuration examples

### ip4_route_custom_documentation.md
**Size**: Technical reference  
**Audience**: Advanced users with multiple interfaces  
**Content**:
- Custom routing implementation
- Source-based routing
- Multi-interface support
- Routing hook details

---

## ?? Learning Path

### Beginner
1. Read **ARCHITECTURE** overview
2. Follow **APPLICATION_LIFECYCLE** examples
3. Try non-persistent TCP sends
4. Implement proper shutdown

### Intermediate
1. Switch to persistent connections
2. Enable keep-alive
3. Implement error handling
4. Monitor performance

### Advanced
1. Use batch send optimization
2. Tune lwIP configuration
3. Implement SSL/TLS
4. Optimize for your use case

---

## ?? Additional Resources

### Source Code
- `wrapper/lwip_wrapper.c/.h` - Main TCP/UDP implementation
- `wrapper/lwip_wrapper_ssl.cpp/.h` - SSL/TLS implementation
- `config/lwipopts.h` - lwIP configuration

### lwIP Documentation
- [lwIP Wiki](https://lwip.fandom.com/wiki/LwIP_Wiki)
- [lwIP Mailing List](https://lists.nongnu.org/mailman/listinfo/lwip-users)

### BoringSSL Documentation
- [BoringSSL GitHub](https://github.com/google/boringssl)

---

## ?? Support

For issues or questions:
1. Check **Troubleshooting** section in ARCHITECTURE
2. Review relevant feature guide
3. Check source code comments
4. Consult lwIP community resources

---

**Happy coding! ??**
