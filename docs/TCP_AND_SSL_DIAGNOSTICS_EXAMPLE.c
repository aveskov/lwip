/**
 * @file TCP_AND_SSL_DIAGNOSTICS_EXAMPLE.c
 * @brief Example showing how to use diagnostic functions for both TCP and SSL connections
 */

#include <stdio.h>
#include <windows.h>
#include "lwip_wrapper.h"
#include "lwip_wrapper_ssl.h"

// Example 1: Monitor TCP persistent connection
void monitor_tcp_connection(const char* conn_id) {
    printf("=== Monitoring TCP Connection '%s' ===\n\n", conn_id);
    
    // Get pending ACK count
    int tcp_pending_count = lwip_tcp_get_pending_ack_count(conn_id);
    printf("TCP pending ACKs: %d messages\n", tcp_pending_count);
    
    // Get pending bytes
    int tcp_pending_bytes = lwip_tcp_get_pending_ack_bytes(conn_id);
    printf("TCP pending bytes: %d\n", tcp_pending_bytes);
    
    // Get TCP send buffer availability
    int tcp_buffer_avail = lwip_tcp_get_send_buffer_available(conn_id);
    printf("TCP send buffer available: %d bytes\n", tcp_buffer_avail);
    
    // Print detailed state
    printf("\nDetailed TCP State:\n");
    lwip_tcp_print_ack_queue_state(conn_id);
}

// Example 2: Monitor SSL connection
void monitor_ssl_connection(const char* conn_id) {
    printf("=== Monitoring SSL Connection '%s' ===\n\n", conn_id);
    
    // Check if connected
    int is_connected = lwip_ssl_is_connected(conn_id);
    printf("SSL connection status: %s\n", is_connected ? "CONNECTED" : "NOT CONNECTED");
    
    if (is_connected) {
        // Get pending ACK count
        int ssl_pending_count = lwip_ssl_get_pending_ack_count(conn_id);
        printf("SSL pending ACKs: %d messages\n", ssl_pending_count);
        
        // Get pending bytes
        int ssl_pending_bytes = lwip_ssl_get_pending_ack_bytes(conn_id);
        printf("SSL pending bytes: %d\n", ssl_pending_bytes);
        
        // Print detailed state
        printf("\nDetailed SSL State:\n");
        lwip_ssl_print_ack_queue_state(conn_id);
    }
}

// Example 3: Compare TCP vs SSL connection health
void compare_connections(const char* tcp_conn_id, const char* ssl_conn_id) {
    printf("\n=== Connection Comparison ===\n\n");
    
    int tcp_pending = lwip_tcp_get_pending_ack_count(tcp_conn_id);
    int ssl_pending = lwip_ssl_get_pending_ack_count(ssl_conn_id);
    
    printf("TCP connection '%s': %d pending ACKs\n", tcp_conn_id, tcp_pending);
    printf("SSL connection '%s': %d pending ACKs\n", ssl_conn_id, ssl_pending);
    
    // Determine which is healthier
    if (tcp_pending >= 0 && ssl_pending >= 0) {
        if (tcp_pending < ssl_pending) {
            printf("\nTCP connection is healthier (fewer pending ACKs)\n");
        } else if (ssl_pending < tcp_pending) {
            printf("\nSSL connection is healthier (fewer pending ACKs)\n");
        } else {
            printf("\nBoth connections have equal ACK queue size\n");
        }
        
        // Check for warnings
        if (tcp_pending > 20) {
            printf("WARNING: TCP connection has high ACK queue!\n");
        }
        if (ssl_pending > 20) {
            printf("WARNING: SSL connection has high ACK queue!\n");
        }
    }
}

// Example 4: Monitoring thread for continuous health checks
typedef struct {
    const char* tcp_conn_id;
    const char* ssl_conn_id;
    volatile int* running;
} monitor_params_t;

DWORD WINAPI continuous_monitor_thread(LPVOID param) {
    monitor_params_t* params = (monitor_params_t*)param;
    
    printf("[MONITOR] Started continuous monitoring thread\n");
    
    while (*params->running) {
        printf("\n========== Health Check ==========\n");
        
        // Check TCP connection
        if (params->tcp_conn_id) {
            int tcp_pending = lwip_tcp_get_pending_ack_count(params->tcp_conn_id);
            int tcp_bytes = lwip_tcp_get_pending_ack_bytes(params->tcp_conn_id);
            printf("[TCP] Pending: %d messages, %d bytes\n", tcp_pending, tcp_bytes);
            
            if (tcp_pending > 15) {
                printf("[TCP] WARNING: High ACK queue detected!\n");
            }
        }
        
        // Check SSL connection
        if (params->ssl_conn_id) {
            int ssl_pending = lwip_ssl_get_pending_ack_count(params->ssl_conn_id);
            int ssl_bytes = lwip_ssl_get_pending_ack_bytes(params->ssl_conn_id);
            printf("[SSL] Pending: %d messages, %d bytes\n", ssl_pending, ssl_bytes);
            
            if (ssl_pending > 15) {
                printf("[SSL] WARNING: High ACK queue detected!\n");
            }
        }
        
        printf("==================================\n");
        
        Sleep(2000);  // Check every 2 seconds
    }
    
    printf("[MONITOR] Monitor thread stopped\n");
    return 0;
}

// Example 5: Safe send with queue checking (works for both TCP and SSL)
int safe_tcp_send_with_queue_check(const char* conn_id, 
                                     const uint8_t* data, 
                                     int len, 
                                     const char* msg_id) {
    // Check queue before sending
    int pending = lwip_tcp_get_pending_ack_count(conn_id);
    
    if (pending > 20) {
        printf("[TCP] Queue full (%d), waiting...\n", pending);
        
        // Wait for queue to drain
        int wait_count = 0;
        while (pending > 15 && wait_count < 100) {
            Sleep(50);
            pending = lwip_tcp_get_pending_ack_count(conn_id);
            wait_count++;
        }
        
        if (pending > 20) {
            printf("[TCP] ERROR: Queue still full after waiting\n");
            lwip_tcp_print_ack_queue_state(conn_id);
            return -3;
        }
    }
    
    // Send
    return lwip_tcp_send_persistent(conn_id, data, len, msg_id);
}

int safe_ssl_send_with_queue_check(const char* conn_id, 
                                     const uint8_t* data, 
                                     int len, 
                                     const char* msg_id) {
    // Check queue before sending
    int pending = lwip_ssl_get_pending_ack_count(conn_id);
    
    if (pending > 20) {
        printf("[SSL] Queue full (%d), waiting...\n", pending);
        
        // Wait for queue to drain
        int wait_count = 0;
        while (pending > 15 && wait_count < 100) {
            Sleep(50);
            pending = lwip_ssl_get_pending_ack_count(conn_id);
            wait_count++;
        }
        
        if (pending > 20) {
            printf("[SSL] ERROR: Queue still full after waiting\n");
            lwip_ssl_print_ack_queue_state(conn_id);
            return -3;
        }
    }
    
    // Send
    return lwip_ssl_send_persistent(conn_id, data, len, msg_id);
}

// Example 6: Full demo
int main() {
    printf("=== TCP and SSL Diagnostics Demo ===\n\n");
    
    // Initialize
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();
    
    // Create base connection
    const char* conn_id = "test_conn";
    lwip_create_connection(conn_id, "192.168.1.100", "255.255.255.0", "192.168.1.1", NULL, NULL);
    
    // Create TCP persistent connection
    const char* tcp_conn_id = "tcp_conn";
    lwip_create_connection(tcp_conn_id, "192.168.1.101", "255.255.255.0", "192.168.1.1", NULL, NULL);
    lwip_tcp_connect_persistent(tcp_conn_id, "192.168.1.50", 8080, NULL);
    
    // Create SSL persistent connection
    const char* ssl_conn_id = "ssl_conn";
    lwip_ssl_connect_persistent(ssl_conn_id, "192.168.1.50", 443, "example.com", NULL, NULL, NULL);
    
    // Wait for connections
    Sleep(1000);
    
    // Demo 1: Monitor individual connections
    printf("\n--- Individual Connection Monitoring ---\n");
    monitor_tcp_connection(tcp_conn_id);
    monitor_ssl_connection(ssl_conn_id);
    
    // Demo 2: Compare connections
    printf("\n--- Connection Comparison ---\n");
    compare_connections(tcp_conn_id, ssl_conn_id);
    
    // Demo 3: Start continuous monitoring
    printf("\n--- Starting Continuous Monitor ---\n");
    volatile int running = 1;
    monitor_params_t params = {tcp_conn_id, ssl_conn_id, &running};
    HANDLE h_monitor = CreateThread(NULL, 0, continuous_monitor_thread, &params, 0, NULL);
    
    // Demo 4: Send some messages with queue checking
    printf("\n--- Sending Test Messages ---\n");
    for (int i = 0; i < 10; i++) {
        char msg_id[32];
        sprintf(msg_id, "tcp_msg_%d", i);
        
        const char* test_data = "Test message";
        int result = safe_tcp_send_with_queue_check(tcp_conn_id, 
                                                      (const uint8_t*)test_data, 
                                                      strlen(test_data), 
                                                      msg_id);
        
        if (result == 0) {
            printf("[TCP] Sent message %d\n", i);
        }
        
        Sleep(100);
    }
    
    // Let monitor run for a bit
    printf("\n--- Monitor Running (5 seconds) ---\n");
    Sleep(5000);
    
    // Stop monitoring
    printf("\n--- Stopping Monitor ---\n");
    running = 0;
    WaitForSingleObject(h_monitor, 2000);
    CloseHandle(h_monitor);
    
    // Final health check
    printf("\n--- Final Health Check ---\n");
    lwip_tcp_print_ack_queue_state(tcp_conn_id);
    lwip_ssl_print_ack_queue_state(ssl_conn_id);
    
    // Cleanup
    printf("\n--- Cleanup ---\n");
    lwip_tcp_disconnect_persistent(tcp_conn_id);
    lwip_ssl_disconnect_persistent(ssl_conn_id);
    lwip_close_connection(tcp_conn_id);
    lwip_close_connection(ssl_conn_id);
    lwip_close_connection(conn_id);
    
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();
    
    printf("\nDemo complete!\n");
    return 0;
}

/**
 * Key API Functions Available:
 * 
 * TCP Diagnostics:
 * - int lwip_tcp_get_pending_ack_count(const char* id)
 * - int lwip_tcp_get_pending_ack_bytes(const char* id)
 * - void lwip_tcp_print_ack_queue_state(const char* id)
 * - int lwip_tcp_get_send_buffer_available(const char* id)
 * 
 * SSL Diagnostics:
 * - int lwip_ssl_get_pending_ack_count(const char* id)
 * - int lwip_ssl_get_pending_ack_bytes(const char* id)
 * - void lwip_ssl_print_ack_queue_state(const char* id)
 * - int lwip_ssl_is_connected(const char* id)
 * 
 * All functions return:
 * - >= 0: Success (count/bytes)
 * - -1: Error (connection not found or not persistent)
 */
