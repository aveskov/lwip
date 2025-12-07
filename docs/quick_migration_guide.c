// Quick Reference: Before and After TCP Performance Optimization

// ============================================================================
// SCENARIO 1: Single Message Send
// ============================================================================

// BEFORE (slower - Nagle enabled by default)
lwip_tcp_send("conn1", "192.168.1.200", 8080, "Hello");
// Latency: ~30ms (with 10ms RTT)

// AFTER (automatically faster - Nagle disabled)
lwip_tcp_send("conn1", "192.168.1.200", 8080, "Hello");
// Latency: ~20ms (with 10ms RTT) - NO CODE CHANGE NEEDED!


// ============================================================================
// SCENARIO 2: Multiple Messages to Same Destination
// ============================================================================

// BEFORE (very slow - creates new connection each time)
for (int i = 0; i < 100; i++) {
    lwip_tcp_send("conn1", "192.168.1.200", 8080, "Hello");
    lwip_poll();
    // Wait for connection complete...
}
// Total time: ~3000ms (with 10ms RTT)

// AFTER (much faster - persistent connection)
lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
lwip_poll(); // Wait for connection

for (int i = 0; i < 100; i++) {
    uint8_t msg[] = "Hello";
    lwip_tcp_send_persistent("conn1", msg, sizeof(msg) - 1);
    lwip_poll();
}

lwip_tcp_disconnect_persistent("conn1");
// Total time: ~1000ms (with 10ms RTT) - 3X FASTER!


// ============================================================================
// SCENARIO 3: Fine-tuning Nagle's Algorithm
// ============================================================================

// For real-time applications (low latency priority)
lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
lwip_tcp_set_nodelay("conn1", 1); // Disable Nagle (already default)

// For bulk transfers (throughput priority)
lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
lwip_tcp_set_nodelay("conn1", 0); // Enable Nagle to batch small packets


// ============================================================================
// COMPLETE EXAMPLE: Chat Application
// ============================================================================

// BEFORE (slow)
void send_chat_messages() {
    for (int i = 0; i < 10; i++) {
        char msg[100];
        sprintf(msg, "Message %d", i);
        lwip_tcp_send("chat", "192.168.1.200", 8080, msg);
        lwip_poll();
        Sleep(10); // Wait for connection to complete
    }
    // Total time: ~300ms + network latency
}

// AFTER (fast)
void send_chat_messages() {
    // Connect once
    lwip_tcp_connect_persistent("chat", "192.168.1.200", 8080);
    lwip_poll();
    Sleep(10); // Wait for initial connection only
    
    // Send all messages
    for (int i = 0; i < 10; i++) {
        char msg[100];
        sprintf(msg, "Message %d", i);
        lwip_tcp_send_persistent("chat", (uint8_t*)msg, strlen(msg));
        lwip_poll();
    }
    
    // Disconnect once (or keep connection for future sends)
    lwip_tcp_disconnect_persistent("chat");
    // Total time: ~100ms + network latency - 3X FASTER!
}


// ============================================================================
// COMPLETE EXAMPLE: Sensor Data Logger
// ============================================================================

// BEFORE (inefficient)
void log_sensor_data() {
    while (running) {
        float temperature = read_temperature();
        char data[50];
        sprintf(data, "TEMP:%.2f", temperature);
        
        // Creates new connection every second!
        lwip_tcp_send("logger", "192.168.1.200", 9000, data);
        lwip_poll();
        Sleep(1000);
    }
}

// AFTER (efficient)
void log_sensor_data() {
    // Establish persistent connection at startup
    lwip_tcp_connect_persistent("logger", "192.168.1.200", 9000);
    lwip_poll();
    Sleep(10);
    
    while (running) {
        float temperature = read_temperature();
        char data[50];
        sprintf(data, "TEMP:%.2f", temperature);
        
        // Reuse existing connection - much faster!
        lwip_tcp_send_persistent("logger", (uint8_t*)data, strlen(data));
        lwip_poll();
        Sleep(1000);
    }
    
    // Close connection on shutdown
    lwip_tcp_disconnect_persistent("logger");
}


// ============================================================================
// MIGRATION CHECKLIST
// ============================================================================

/*
1. For single sends:
   ? No action needed - automatically faster!

2. For multiple sends to same destination:
   ? Change to persistent connection pattern:
      - Connect once with lwip_tcp_connect_persistent()
      - Use lwip_tcp_send_persistent() for all sends
      - Disconnect with lwip_tcp_disconnect_persistent()

3. For real-time data:
   ? Verify Nagle is disabled (default in optimized version)
   ? Use lwip_tcp_set_nodelay("id", 1) if needed

4. For high throughput:
   ? Consider enabling Nagle: lwip_tcp_set_nodelay("id", 0)

5. Testing:
   ? Measure latency before and after
   ? Verify callbacks work correctly
   ? Check for connection leaks (proper disconnect)
*/
