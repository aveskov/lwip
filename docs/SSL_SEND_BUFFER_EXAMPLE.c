/**
 * @file SSL_SEND_BUFFER_EXAMPLE.c
 * @brief Example showing how to use lwip_ssl_get_send_buffer_available()
 */

#include <stdio.h>
#include <windows.h>
#include "lwip_wrapper.h"
#include "lwip_wrapper_ssl.h"

/**
 * Example 1: Check buffer before sending
 */
void example_check_before_send(const char* ssl_conn_id) {
    const uint8_t* data = (const uint8_t*)"Large message data...";
    int len = strlen((const char*)data);
    
    // Check TCP send buffer availability
    int buffer_avail = lwip_ssl_get_send_buffer_available(ssl_conn_id);
    
    if (buffer_avail < 0) {
        printf("ERROR: Cannot get buffer availability (connection not ready)\n");
        return;
    }
    
    printf("TCP send buffer available: %d bytes\n", buffer_avail);
    
    if (buffer_avail >= len) {
        printf("Buffer has enough space, sending %d bytes...\n", len);
        int result = lwip_ssl_send_persistent(ssl_conn_id, data, len, "msg_123");
        
        if (result == 0) {
            printf("Send successful\n");
        } else {
            printf("Send failed with code: %d\n", result);
        }
    } else {
        printf("WARNING: Insufficient buffer space (%d < %d)\n", buffer_avail, len);
        printf("Waiting for buffer to drain...\n");
        
        // Wait and retry
        Sleep(50);
        lwip_poll();
        
        buffer_avail = lwip_ssl_get_send_buffer_available(ssl_conn_id);
        printf("Buffer after wait: %d bytes\n", buffer_avail);
    }
}

/**
 * Example 2: Monitor buffer usage during high-rate sending
 */
void example_monitor_buffer_usage(const char* ssl_conn_id) {
    printf("\n=== Monitoring SSL Buffer Usage ===\n");
    
    const char* test_data = "Test message for SSL";
    int msg_count = 0;
    
    for (int i = 0; i < 100; i++) {
        // Check buffer before each send
        int buffer_avail = lwip_ssl_get_send_buffer_available(ssl_conn_id);
        
        if (buffer_avail < 0) {
            printf("ERROR: Connection lost\n");
            break;
        }
        
        // Calculate buffer usage percentage
        int buffer_max = 2048;  // TCP_SND_BUF default
        float usage_pct = ((buffer_max - buffer_avail) * 100.0) / buffer_max;
        
        printf("[%d] Buffer: %d/%d bytes free (%.1f%% used)\n", 
               i, buffer_avail, buffer_max, usage_pct);
        
        // Warn if buffer is getting full
        if (usage_pct > 75.0) {
            printf("WARNING: High buffer usage! Slowing down...\n");
            Sleep(100);
            lwip_poll();
            continue;
        }
        
        // Send message
        char msg_id[32];
        sprintf(msg_id, "msg_%d", i);
        
        int result = lwip_ssl_send_persistent(ssl_conn_id, 
                                               (const uint8_t*)test_data, 
                                               strlen(test_data), 
                                               msg_id);
        
        if (result == 0) {
            msg_count++;
        } else if (result == -2) {
            printf("Buffer full, retrying...\n");
            i--;  // Retry this message
            Sleep(50);
            lwip_poll();
        } else {
            printf("ERROR: Send failed\n");
            break;
        }
        
        // Small delay between sends
        Sleep(10);
        
        // Poll regularly
        if (i % 5 == 0) {
            lwip_poll();
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Messages sent: %d\n", msg_count);
    
    // Final buffer check
    int final_buffer = lwip_ssl_get_send_buffer_available(ssl_conn_id);
    printf("Final buffer available: %d bytes\n", final_buffer);
}

/**
 * Example 3: Compare TCP vs SSL buffer availability
 */
void example_compare_tcp_ssl_buffers(const char* tcp_conn_id, const char* ssl_conn_id) {
    printf("\n=== Buffer Comparison: TCP vs SSL ===\n");
    
    int tcp_buffer = lwip_tcp_get_send_buffer_available(tcp_conn_id);
    int ssl_buffer = lwip_ssl_get_send_buffer_available(ssl_conn_id);
    
    printf("TCP connection buffer: %d bytes\n", tcp_buffer);
    printf("SSL connection buffer: %d bytes\n", ssl_buffer);
    
    // Note: Both use the same underlying TCP buffer
    // SSL has additional overhead for encryption
    
    if (tcp_buffer > 0 && ssl_buffer > 0) {
        printf("\nBoth connections have available buffer space\n");
    } else {
        if (tcp_buffer <= 0) printf("WARNING: TCP buffer full or not available\n");
        if (ssl_buffer <= 0) printf("WARNING: SSL buffer full or not available\n");
    }
}

/**
 * Example 4: Adaptive send rate based on buffer
 */
int adaptive_ssl_send(const char* ssl_conn_id, 
                      const uint8_t* data, 
                      int len, 
                      const char* msg_id) {
    // Check buffer availability
    int buffer_avail = lwip_ssl_get_send_buffer_available(ssl_conn_id);
    
    if (buffer_avail < 0) {
        printf("ERROR: Cannot get buffer status\n");
        return -1;
    }
    
    // Calculate delay based on buffer availability
    int delay_ms = 0;
    
    if (buffer_avail > 1536) {
        // >75% free - full speed
        delay_ms = 0;
    } else if (buffer_avail > 1024) {
        // 50-75% free - normal speed
        delay_ms = 10;
    } else if (buffer_avail > 512) {
        // 25-50% free - slow down
        delay_ms = 50;
    } else {
        // <25% free - very slow
        delay_ms = 100;
        printf("WARNING: Low buffer (%d bytes), slowing down\n", buffer_avail);
    }
    
    // Apply delay
    if (delay_ms > 0) {
        Sleep(delay_ms);
        lwip_poll();
    }
    
    // Wait if buffer is too full
    int wait_count = 0;
    while (buffer_avail < len && wait_count < 50) {
        printf("Buffer full (%d < %d), waiting...\n", buffer_avail, len);
        Sleep(50);
        lwip_poll();
        buffer_avail = lwip_ssl_get_send_buffer_available(ssl_conn_id);
        wait_count++;
    }
    
    if (buffer_avail < len) {
        printf("ERROR: Timeout waiting for buffer space\n");
        return -2;
    }
    
    // Send
    return lwip_ssl_send_persistent(ssl_conn_id, data, len, msg_id);
}

/**
 * Example 5: Monitor buffer in background thread
 */
typedef struct {
    const char* ssl_conn_id;
    volatile int* running;
} buffer_monitor_params_t;

DWORD WINAPI buffer_monitor_thread(LPVOID param) {
    buffer_monitor_params_t* params = (buffer_monitor_params_t*)param;
    
    printf("[BUFFER MONITOR] Started\n");
    
    int low_buffer_count = 0;
    
    while (*params->running) {
        int buffer_avail = lwip_ssl_get_send_buffer_available(params->ssl_conn_id);
        
        if (buffer_avail < 0) {
            printf("[BUFFER MONITOR] Connection not available\n");
            Sleep(1000);
            continue;
        }
        
        // Calculate usage
        int buffer_max = 2048;
        float usage_pct = ((buffer_max - buffer_avail) * 100.0) / buffer_max;
        
        printf("[BUFFER MONITOR] Available: %d/%d bytes (%.1f%% used)\n", 
               buffer_avail, buffer_max, usage_pct);
        
        // Alert on low buffer
        if (buffer_avail < 512) {
            low_buffer_count++;
            printf("[BUFFER MONITOR] ALERT: Low buffer detected (%d times)\n", 
                   low_buffer_count);
            
            // Print detailed state
            lwip_ssl_print_ack_queue_state(params->ssl_conn_id);
        }
        
        Sleep(500);  // Check every 500ms
    }
    
    printf("[BUFFER MONITOR] Stopped (low buffer alerts: %d)\n", low_buffer_count);
    return 0;
}

/**
 * Main demo
 */
int main() {
    printf("=== SSL Send Buffer Availability Demo ===\n\n");
    
    // Initialize
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();
    
    // Create connections
    const char* conn_id = "ssl_demo";
    lwip_create_connection(conn_id, "192.168.1.100", "255.255.255.0", "192.168.1.1", NULL, NULL);
    lwip_ssl_connect_persistent(conn_id, "192.168.1.50", 443, "example.com", NULL, NULL, NULL);
    
    // Wait for connection
    printf("Waiting for SSL connection...\n");
    Sleep(1000);
    
    if (!lwip_ssl_is_connected(conn_id)) {
        printf("ERROR: SSL connection failed\n");
        return 1;
    }
    
    printf("SSL connection established!\n\n");
    
    // Get initial buffer status
    int initial_buffer = lwip_ssl_get_send_buffer_available(conn_id);
    printf("Initial TCP send buffer: %d bytes\n\n", initial_buffer);
    
    // Example 1: Check before send
    printf("=== Example 1: Check Before Send ===\n");
    example_check_before_send(conn_id);
    
    // Example 2: Monitor during high-rate sending
    printf("\n=== Example 2: Monitor During High-Rate Sending ===\n");
    example_monitor_buffer_usage(conn_id);
    
    // Example 4: Adaptive send rate
    printf("\n=== Example 4: Adaptive Send Rate ===\n");
    for (int i = 0; i < 10; i++) {
        char msg_id[32];
        sprintf(msg_id, "adaptive_%d", i);
        
        const char* data = "Adaptive rate message";
        int result = adaptive_ssl_send(conn_id, 
                                        (const uint8_t*)data, 
                                        strlen(data), 
                                        msg_id);
        
        printf("Message %d: %s\n", i, result == 0 ? "OK" : "FAILED");
    }
    
    // Example 5: Background monitoring
    printf("\n=== Example 5: Background Buffer Monitoring ===\n");
    volatile int running = 1;
    buffer_monitor_params_t monitor_params = {conn_id, &running};
    HANDLE h_monitor = CreateThread(NULL, 0, buffer_monitor_thread, &monitor_params, 0, NULL);
    
    // Let monitor run while we send
    printf("Sending messages while monitoring...\n");
    for (int i = 0; i < 20; i++) {
        char msg_id[32];
        sprintf(msg_id, "monitored_%d", i);
        
        const char* data = "Message during monitoring";
        lwip_ssl_send_persistent(conn_id, (const uint8_t*)data, strlen(data), msg_id);
        Sleep(100);
    }
    
    // Stop monitor
    Sleep(2000);
    running = 0;
    WaitForSingleObject(h_monitor, 2000);
    CloseHandle(h_monitor);
    
    // Final status
    printf("\n=== Final Status ===\n");
    int final_buffer = lwip_ssl_get_send_buffer_available(conn_id);
    printf("Final buffer available: %d bytes\n", final_buffer);
    
    lwip_ssl_print_ack_queue_state(conn_id);
    
    // Cleanup
    printf("\n=== Cleanup ===\n");
    lwip_ssl_disconnect_persistent(conn_id);
    lwip_close_connection(conn_id);
    
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();
    
    printf("\nDemo complete!\n");
    return 0;
}

/**
 * KEY POINTS:
 * 
 * 1. lwip_ssl_get_send_buffer_available() returns:
 *    - >= 0: TCP send buffer space available (in bytes)
 *    - -1: Error (connection not found, not connected, or not persistent)
 * 
 * 2. Same function is available for TCP:
 *    - lwip_tcp_get_send_buffer_available()
 * 
 * 3. Both TCP and SSL share the same underlying TCP send buffer
 *    - SSL messages have encryption overhead (~30 bytes)
 *    - So effective space for SSL is slightly less
 * 
 * 4. Typical TCP_SND_BUF size: 2048 bytes
 *    - Adjust based on your lwipopts.h configuration
 * 
 * 5. Use buffer checking to:
 *    - Prevent send failures (return code -2)
 *    - Implement adaptive rate limiting
 *    - Monitor connection health
 *    - Avoid message loss
 * 
 * 6. Best practices:
 *    - Check buffer before large sends
 *    - Monitor buffer usage during high-rate sending
 *    - Wait/retry if buffer is full
 *    - Call lwip_poll() regularly to drain buffer
 */
