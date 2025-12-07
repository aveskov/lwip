/**
 * @file SSL_ACK_MONITORING_EXAMPLE.c
 * @brief Example showing how to monitor and prevent unbounded ACK queue growth
 * 
 * This example demonstrates:
 * 1. Monitoring ACK queue size in real-time
 * 2. Implementing rate limiting based on queue size
 * 3. Detecting and handling ACK queue growth issues
 * 4. Using diagnostic functions to troubleshoot
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "lwip_wrapper.h"
#include "lwip_wrapper_ssl.h"

// Configuration
#define MAX_PENDING_ACKS 15        // Stop sending if queue exceeds this
#define WARNING_THRESHOLD 10       // Warn if queue exceeds this
#define MONITOR_INTERVAL_MS 1000   // How often to check queue

// Global state
static volatile LONG running = 1;
static volatile LONG messages_sent = 0;
static volatile LONG acks_received = 0;
static volatile LONG send_errors = 0;

// ACK callback - called when TCP ACKs a message
void on_ack_received(const char* message_id) {
    InterlockedIncrement(&acks_received);
    
    // Parse message number from ID
    int msg_num = 0;
    if (sscanf(message_id, "msg_%d", &msg_num) == 1) {
        printf("[ACK] Received ACK for message #%d (total ACKs: %ld)\n", 
               msg_num, acks_received);
    }
}

// Monitor thread - watches ACK queue health
DWORD WINAPI monitor_thread(LPVOID param) {
    const char* conn_id = (const char*)param;
    
    printf("[MONITOR] Started monitoring thread\n");
    
    while (running) {
        Sleep(MONITOR_INTERVAL_MS);
        
        int pending = lwip_ssl_get_pending_ack_count(conn_id);
        int pending_bytes = lwip_ssl_get_pending_ack_bytes(conn_id);
        
        if (pending < 0) {
            // Connection might be closed
            continue;
        }
        
        // Calculate statistics
        long sent = messages_sent;
        long acked = acks_received;
        long in_flight = sent - acked;
        
        printf("[MONITOR] Sent: %ld, ACK'd: %ld, In-flight: %ld, Queue: %d msgs (%d bytes)\n",
               sent, acked, in_flight, pending, pending_bytes);
        
        // Check for warning conditions
        if (pending > WARNING_THRESHOLD) {
            printf("[WARNING] ACK queue is growing! %d pending messages\n", pending);
            
            if (pending > MAX_PENDING_ACKS) {
                printf("[CRITICAL] ACK queue limit reached! %d > %d\n", 
                       pending, MAX_PENDING_ACKS);
                printf("[CRITICAL] Printing detailed queue state:\n");
                lwip_ssl_print_ack_queue_state(conn_id);
            }
        }
        
        // Check if ACKs have stalled
        static long last_ack_count = 0;
        if (pending > 0 && acked == last_ack_count) {
            printf("[WARNING] ACK processing appears stalled! No new ACKs received.\n");
            printf("[WARNING] Check that lwip_poll() is being called regularly!\n");
        }
        last_ack_count = acked;
    }
    
    printf("[MONITOR] Monitor thread stopped\n");
    return 0;
}

// Polling thread - CRITICAL for processing TCP ACKs
DWORD WINAPI poll_thread(LPVOID param) {
    printf("[POLL] Started polling thread\n");
    
    while (running) {
        lwip_poll();  // Process TCP ACKs and timers
        Sleep(50);    // 20 Hz polling rate
    }
    
    printf("[POLL] Poll thread stopped\n");
    return 0;
}

// Safe send with backpressure - waits if queue is full
int safe_send_with_backpressure(const char* conn_id, 
                                  const uint8_t* data, 
                                  int len, 
                                  const char* msg_id) {
    // Check queue size before sending
    int pending = lwip_ssl_get_pending_ack_count(conn_id);
    
    if (pending >= MAX_PENDING_ACKS) {
        printf("[SEND] Queue full (%d pending), waiting for ACKs...\n", pending);
        
        // Wait for queue to drain
        int wait_count = 0;
        while (pending >= MAX_PENDING_ACKS && wait_count < 100) {
            Sleep(50);
            pending = lwip_ssl_get_pending_ack_count(conn_id);
            wait_count++;
        }
        
        if (pending >= MAX_PENDING_ACKS) {
            printf("[ERROR] Timeout waiting for ACK queue to drain\n");
            InterlockedIncrement(&send_errors);
            return -3;  // Queue still full
        }
        
        printf("[SEND] Queue drained to %d, resuming sends\n", pending);
    }
    
    // Send the message
    int result = lwip_ssl_send_persistent(conn_id, data, len, msg_id);
    
    if (result == 0) {
        InterlockedIncrement(&messages_sent);
    } else {
        InterlockedIncrement(&send_errors);
        
        if (result == -2) {
            printf("[ERROR] Send failed: TCP buffer full (retry later)\n");
        } else {
            printf("[ERROR] Send failed with error code: %d\n", result);
        }
    }
    
    return result;
}

// Example: Burst send test with monitoring
void test_burst_send_with_monitoring(const char* conn_id) {
    printf("\n=== Starting Burst Send Test ===\n");
    printf("Sending 1000 messages as fast as possible...\n\n");
    
    const char* test_data = "This is a test message for burst sending";
    int total_to_send = 1000;
    
    DWORD start_time = GetTickCount();
    
    for (int i = 0; i < total_to_send; i++) {
        char msg_id[64];
        sprintf(msg_id, "msg_%d", i);
        
        int result = safe_send_with_backpressure(
            conn_id,
            (const uint8_t*)test_data,
            strlen(test_data),
            msg_id
        );
        
        if (result != 0) {
            printf("[ERROR] Failed to send message %d, stopping test\n", i);
            break;
        }
        
        // Print progress every 100 messages
        if ((i + 1) % 100 == 0) {
            int pending = lwip_ssl_get_pending_ack_count(conn_id);
            printf("[PROGRESS] Sent %d/%d messages, queue: %d pending\n", 
                   i + 1, total_to_send, pending);
        }
    }
    
    DWORD send_duration = GetTickCount() - start_time;
    
    printf("\n=== Send Phase Complete ===\n");
    printf("Sent: %ld messages in %lu ms (%.1f msg/sec)\n",
           messages_sent, send_duration, 
           (messages_sent * 1000.0) / send_duration);
    printf("Waiting for all ACKs...\n\n");
    
    // Wait for all ACKs to arrive
    int pending;
    int wait_iterations = 0;
    while ((pending = lwip_ssl_get_pending_ack_count(conn_id)) > 0) {
        printf("[WAITING] %d ACKs remaining...\n", pending);
        Sleep(500);
        
        if (++wait_iterations > 60) {  // 30 seconds timeout
            printf("[ERROR] Timeout waiting for ACKs! %d still pending\n", pending);
            lwip_ssl_print_ack_queue_state(conn_id);
            break;
        }
    }
    
    DWORD total_duration = GetTickCount() - start_time;
    
    printf("\n=== Test Complete ===\n");
    printf("Total time: %lu ms\n", total_duration);
    printf("Messages sent: %ld\n", messages_sent);
    printf("ACKs received: %ld\n", acks_received);
    printf("Send errors: %ld\n", send_errors);
    printf("Final queue state:\n");
    lwip_ssl_print_ack_queue_state(conn_id);
}

// Example: Controlled rate send test
void test_rate_limited_send(const char* conn_id) {
    printf("\n=== Starting Rate-Limited Send Test ===\n");
    printf("Sending with 10ms delay between messages...\n\n");
    
    const char* test_data = "Rate limited test message";
    int total_to_send = 100;
    
    for (int i = 0; i < total_to_send; i++) {
        char msg_id[64];
        sprintf(msg_id, "rate_msg_%d", i);
        
        int result = lwip_ssl_send_persistent(
            conn_id,
            (const uint8_t*)test_data,
            strlen(test_data),
            msg_id
        );
        
        if (result == 0) {
            InterlockedIncrement(&messages_sent);
        } else {
            InterlockedIncrement(&send_errors);
            printf("[ERROR] Send failed: %d\n", result);
        }
        
        // Rate limiting - 10ms between sends
        Sleep(10);
        
        if ((i + 1) % 10 == 0) {
            int pending = lwip_ssl_get_pending_ack_count(conn_id);
            printf("[PROGRESS] Sent %d/%d, queue: %d\n", i + 1, total_to_send, pending);
        }
    }
    
    printf("\n=== Rate-Limited Test Complete ===\n");
    printf("With rate limiting, queue should stay small:\n");
    lwip_ssl_print_ack_queue_state(conn_id);
}

int main() {
    printf("=== SSL ACK Monitoring Example ===\n\n");
    
    // Initialize
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();
    
    // Create base connection
    const char* conn_id = "ssl_monitor_test";
    int result = lwip_create_connection(
        conn_id,
        "192.168.1.100",
        "255.255.255.0",
        "192.168.1.1",
        NULL,  // UDP callback
        NULL   // TCP send complete callback
    );
    
    if (result != 0) {
        printf("ERROR: Failed to create base connection\n");
        return 1;
    }
    
    // Create persistent SSL connection with ACK callback
    result = lwip_ssl_connect_persistent(
        conn_id,
        "192.168.1.50",  // Destination IP
        443,             // HTTPS port
        "example.com",   // Hostname for SNI
        NULL,            // Handshake complete callback
        NULL,            // Data received callback
        on_ack_received  // ACK callback - IMPORTANT!
    );
    
    if (result != 0) {
        printf("ERROR: Failed to create SSL connection\n");
        return 1;
    }
    
    printf("Waiting for SSL handshake...\n");
    Sleep(1000);
    
    if (!lwip_ssl_is_connected(conn_id)) {
        printf("ERROR: SSL connection not established\n");
        return 1;
    }
    
    printf("SSL connection established!\n\n");
    
    // Start monitoring threads
    HANDLE h_monitor = CreateThread(NULL, 0, monitor_thread, (LPVOID)conn_id, 0, NULL);
    HANDLE h_poll = CreateThread(NULL, 0, poll_thread, NULL, 0, NULL);
    
    // Run tests
    printf("Choose test:\n");
    printf("1. Burst send (stress test)\n");
    printf("2. Rate-limited send (controlled)\n");
    printf("Enter choice: ");
    
    int choice = 1;
    scanf("%d", &choice);
    
    if (choice == 1) {
        test_burst_send_with_monitoring(conn_id);
    } else {
        test_rate_limited_send(conn_id);
    }
    
    // Print final statistics
    printf("\n=== Final Statistics ===\n");
    printf("Messages sent: %ld\n", messages_sent);
    printf("ACKs received: %ld\n", acks_received);
    printf("Send errors: %ld\n", send_errors);
    printf("Success rate: %.1f%%\n", 
           (acks_received * 100.0) / messages_sent);
    
    // Cleanup
    printf("\nCleaning up...\n");
    running = 0;
    WaitForSingleObject(h_monitor, 2000);
    WaitForSingleObject(h_poll, 2000);
    CloseHandle(h_monitor);
    CloseHandle(h_poll);
    
    lwip_ssl_disconnect_persistent(conn_id);
    lwip_close_connection(conn_id);
    
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();
    
    printf("\nExample complete!\n");
    return 0;
}

/**
 * KEY TAKEAWAYS:
 * 
 * 1. ALWAYS call lwip_poll() regularly (every 50ms)
 *    - This processes TCP ACKs
 *    - Without this, ACK queue will grow unbounded
 * 
 * 2. Monitor ACK queue size with diagnostic functions
 *    - lwip_ssl_get_pending_ack_count()
 *    - lwip_ssl_get_pending_ack_bytes()
 *    - lwip_ssl_print_ack_queue_state()
 * 
 * 3. Implement rate limiting or backpressure
 *    - Check queue size before sending
 *    - Wait if queue exceeds threshold
 *    - Reject sends if queue is full
 * 
 * 4. Track send/ACK statistics
 *    - Messages sent vs ACKs received
 *    - Detect stalled ACK processing
 *    - Calculate success rates
 * 
 * 5. Handle errors appropriately
 *    - Return code -2 = TCP buffer full (retry)
 *    - Return code -1 = Fatal error (stop)
 *    - Return code -3 = Queue full (wait or reject)
 */
