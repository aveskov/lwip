/*
 * TCP Performance Optimization Examples
 * 
 * This file demonstrates how to use the optimized TCP functions to reduce
 * message send time in lwip_wrapper.
 */

#include "lwip_wrapper.h"
#include <stdio.h>
#include <time.h>

// Example callbacks
void my_udp_callback(uint8_t* data, int len) {
    printf("UDP callback: %d bytes\n", len);
}

void my_send_complete_callback(void) {
    printf("Send complete\n");
}

/*
 * OPTION 1: Original Method (SLOWER)
 * 
 * Each call creates a new TCP connection (SYN handshake), sends data, and closes.
 * Typical overhead: ~3 RTT (Round Trip Times)
 *   - 1 RTT for SYN/SYN-ACK/ACK handshake
 *   - 1 RTT for data transmission
 *   - 1 RTT for FIN/FIN-ACK/ACK close
 */
void example_original_method() {
    printf("=== Original Method (Slower) ===\n");
    
    // Create connection
    lwip_create_connection("conn1", "192.168.1.100", "255.255.255.0", "192.168.1.1",
                          my_udp_callback, my_send_complete_callback);
    
    clock_t start = clock();
    
    // Each send creates new connection - SLOW!
    for (int i = 0; i < 100; i++) {
        lwip_tcp_send("conn1", "192.168.1.200", 8080, "Hello World");
        lwip_poll(); // Process timeouts
        // Wait for connection to complete and close
        // In real code, you'd need proper synchronization
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Original method: %.3f seconds for 100 sends\n", elapsed);
    
    lwip_close_connection("conn1");
}

/*
 * OPTION 2: Persistent Connection (FASTER)
 * 
 * Connect once, reuse connection for multiple sends, then disconnect.
 * Typical overhead: ~1 RTT + minimal overhead per send
 *   - Initial 1 RTT for SYN handshake (one time)
 *   - <1 RTT per data send (data is pipelined)
 *   - 1 RTT for final close (one time)
 * 
 * Performance gain: 2-3x faster for multiple sends
 */
void example_persistent_connection() {
    printf("\n=== Persistent Connection Method (Faster) ===\n");
    
    // Create connection
    lwip_create_connection("conn2", "192.168.1.100", "255.255.255.0", "192.168.1.1",
                          my_udp_callback, my_send_complete_callback);
    
    clock_t start = clock();
    
    // Connect once (TCP handshake happens here)
    lwip_tcp_connect_persistent("conn2", "192.168.1.200", 8080);
    lwip_poll(); // Wait for connection
    
    // Send multiple messages on same connection - FAST!
    for (int i = 0; i < 100; i++) {
        uint8_t msg[] = "Hello World";
        lwip_tcp_send_persistent("conn2", msg, sizeof(msg) - 1);
        lwip_poll(); // Process
    }
    
    // Disconnect once
    lwip_tcp_disconnect_persistent("conn2");
    lwip_poll();
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Persistent method: %.3f seconds for 100 sends\n", elapsed);
    
    lwip_close_connection("conn2");
}

/*
 * OPTION 3: Nagle Algorithm Control (FINE-TUNING)
 * 
 * Nagle's algorithm batches small sends to reduce packet overhead.
 * - Enable Nagle (default in standard TCP): Better for throughput, adds ~200ms delay
 * - Disable Nagle (TCP_NODELAY): Better for latency, sends immediately
 * 
 * Note: The optimized lwip_tcp_send already disables Nagle by default.
 * This example shows how to manually control it.
 */
void example_nagle_control() {
    printf("\n=== Nagle Algorithm Control ===\n");
    
    lwip_create_connection("conn3", "192.168.1.100", "255.255.255.0", "192.168.1.1",
                          my_udp_callback, my_send_complete_callback);
    
    lwip_tcp_connect_persistent("conn3", "192.168.1.200", 8080);
    lwip_poll();
    
    // Disable Nagle for low-latency (already default in optimized version)
    lwip_tcp_set_nodelay("conn3", 1);
    
    clock_t start = clock();
    uint8_t msg[] = "Small message";
    lwip_tcp_send_persistent("conn3", msg, sizeof(msg) - 1);
    clock_t end = clock();
    
    printf("Send with Nagle disabled: %.3f ms\n", 
           ((double)(end - start)) / CLOCKS_PER_SEC * 1000);
    
    // Enable Nagle for throughput-optimized sends
    lwip_tcp_set_nodelay("conn3", 0);
    
    start = clock();
    lwip_tcp_send_persistent("conn3", msg, sizeof(msg) - 1);
    end = clock();
    
    printf("Send with Nagle enabled: %.3f ms\n", 
           ((double)(end - start)) / CLOCKS_PER_SEC * 1000);
    
    lwip_tcp_disconnect_persistent("conn3");
    lwip_close_connection("conn3");
}

/*
 * PERFORMANCE COMPARISON SUMMARY
 * 
 * Method                  | Single Send | 100 Sends | Best Use Case
 * ------------------------|-------------|-----------|---------------------------
 * lwip_tcp_send (orig)   | ~3 RTT      | ~300 RTT  | One-time sends
 * Persistent + NoDelay   | ~1 RTT      | ~100 RTT  | Multiple sends, low latency
 * Persistent + Nagle     | ~1 RTT      | ~100 RTT  | Multiple sends, throughput
 * 
 * RTT = Round Trip Time (typically 1-100ms depending on network)
 * 
 * RECOMMENDATIONS:
 * 1. For single message: Use lwip_tcp_send (already optimized with NoDelay)
 * 2. For multiple messages: Use persistent connection (2-3x faster)
 * 3. For low latency: Keep Nagle disabled (default in optimized code)
 * 4. For high throughput: Enable Nagle if sending many small packets
 */

int main() {
    lwip_init_stack_global();
    
    printf("TCP Performance Optimization Examples\n");
    printf("======================================\n\n");
    
    // Run examples
    example_original_method();
    example_persistent_connection();
    example_nagle_control();
    
    printf("\n=== Performance Improvement Summary ===\n");
    printf("The optimized lwip_tcp_send now has:\n");
    printf("1. TCP_NODELAY enabled by default (reduced latency)\n");
    printf("2. Persistent connection option (2-3x faster for multiple sends)\n");
    printf("3. Reduced lock contention (better concurrency)\n");
    
    return 0;
}
