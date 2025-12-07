/**
 * @file ssl_persistent_example.c
 * @brief Example demonstrating SSL persistent connection usage
 * 
 * This example shows how to use persistent SSL connections to send
 * multiple messages with ~3x performance improvement compared to
 * creating a new connection for each message.
 */

#include "lwip_wrapper.h"
#include "lwip_wrapper_ssl.h"
#include <stdio.h>
#include <windows.h>

// Message tracking
static int messages_sent = 0;
static int messages_acked = 0;
static int handshake_done = 0;

// Callbacks
void on_handshake_complete(int success) {
    if (success) {
        printf("? SSL handshake completed successfully!\n");
        handshake_done = 1;
    } else {
        printf("? SSL handshake failed!\n");
        handshake_done = -1;
    }
}

void on_data_received(const uint8_t* data, int len) {
    printf("? Received %d bytes from server: %.*s\n", len, len, data);
}

void on_message_sent(const char* message_id) {
    messages_acked++;
    printf("? Message '%s' acknowledged (%d/%d)\n", 
           message_id, messages_acked, messages_sent);
}

void udp_send_callback(uint8_t* data, int len) {
    // Send packet to network (implementation specific)
    printf("? Sending %d bytes to network\n", len);
}

/**
 * Example 1: Basic persistent SSL connection
 */
void example_basic_persistent_ssl() {
    printf("\n=== Example 1: Basic Persistent SSL ===\n");

    // 1. Initialize LwIP and SSL
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();

    // 2. Create base connection for routing
    lwip_create_connection("conn1",
        "192.168.1.10",      // Source IP
        "255.255.255.0",     // Netmask
        "192.168.1.1",       // Gateway
        udp_send_callback,
        NULL);

    // 3. Create persistent SSL connection (handshake only once)
    printf("Initiating SSL connection...\n");
    int result = lwip_ssl_connect_persistent("conn1",
        "10.0.0.100",           // Destination IP
        443,                     // HTTPS port
        "example.com",           // SNI hostname
        on_handshake_complete,   // Handshake callback
        on_data_received,        // Data received callback
        on_message_sent);        // Message ACK callback

    if (result != 0) {
        printf("Failed to initiate SSL connection\n");
        return;
    }

    // 4. Wait for handshake to complete
    printf("Waiting for handshake...\n");
    while (handshake_done == 0) {
        lwip_poll();  // Process network events
        Sleep(50);
    }

    if (handshake_done < 0) {
        printf("Handshake failed, aborting\n");
        return;
    }

    // 5. Send multiple messages (FAST - no handshake overhead!)
    printf("\nSending messages...\n");
    const char* messages[] = {
        "GET /api/status HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /api/info HTTP/1.1\r\nHost: example.com\r\n\r\n"
    };

    for (int i = 0; i < 3; i++) {
        char msg_id[32];
        sprintf(msg_id, "msg_%d", i);

        result = lwip_ssl_send_persistent("conn1",
            (const uint8_t*)messages[i],
            strlen(messages[i]),
            msg_id);

        if (result == 0) {
            messages_sent++;
            printf("? Sent message %d\n", i + 1);
        } else if (result == -2) {
            printf("Buffer full, retrying...\n");
            lwip_poll();
            Sleep(50);
            result = lwip_ssl_send_persistent("conn1",
                (const uint8_t*)messages[i],
                strlen(messages[i]),
                msg_id);
            if (result == 0) {
                messages_sent++;
            }
        } else {
            printf("Send failed with error %d\n", result);
            break;
        }

        // Process network events
        lwip_poll();
        Sleep(100);
    }

    // 6. Wait for all ACKs
    printf("\nWaiting for acknowledgments...\n");
    int timeout = 100; // 10 seconds
    while (messages_acked < messages_sent && timeout-- > 0) {
        lwip_poll();
        Sleep(100);
    }

    printf("\nSummary: %d/%d messages acknowledged\n", 
           messages_acked, messages_sent);

    // 7. Gracefully disconnect
    printf("\nDisconnecting...\n");
    lwip_ssl_disconnect_persistent("conn1");

    // Give time for graceful close
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(100);
    }

    // 8. Cleanup
    lwip_close_connection("conn1");
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();

    printf("Done!\n");
}

/**
 * Example 2: High-throughput message sending
 */
void example_high_throughput() {
    printf("\n=== Example 2: High-Throughput Sending ===\n");

    // Initialize (same as Example 1)
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();

    lwip_create_connection("conn2",
        "192.168.1.10", "255.255.255.0", "192.168.1.1",
        udp_send_callback, NULL);

    // Connect
    printf("Connecting...\n");
    handshake_done = 0;
    messages_sent = 0;
    messages_acked = 0;

    lwip_ssl_connect_persistent("conn2", "10.0.0.100", 443, "api.example.com",
        on_handshake_complete, on_data_received, on_message_sent);

    while (handshake_done == 0) {
        lwip_poll();
        Sleep(50);
    }

    if (handshake_done < 0) return;

    // Send many messages in a loop
    printf("\nSending 100 messages...\n");
    const char* data = "{\"event\":\"ping\",\"timestamp\":12345}";
    int data_len = strlen(data);

    DWORD start_time = GetTickCount();

    for (int i = 0; i < 100; i++) {
        char msg_id[32];
        sprintf(msg_id, "msg_%d", i);

        int result = lwip_ssl_send_persistent("conn2",
            (const uint8_t*)data, data_len, msg_id);

        if (result == -2) {
            // Buffer full - process and retry
            for (int retry = 0; retry < 5; retry++) {
                lwip_poll();
                Sleep(50);
                result = lwip_ssl_send_persistent("conn2",
                    (const uint8_t*)data, data_len, msg_id);
                if (result == 0) break;
            }
        }

        if (result == 0) {
            messages_sent++;
            if ((i + 1) % 10 == 0) {
                printf("Sent %d messages...\n", i + 1);
            }
        } else {
            printf("Failed at message %d\n", i + 1);
            break;
        }

        // Process network events periodically
        if (i % 5 == 0) {
            lwip_poll();
        }
    }

    DWORD elapsed = GetTickCount() - start_time;

    // Wait for ACKs
    printf("\nWaiting for acknowledgments...\n");
    int timeout = 200; // 20 seconds
    while (messages_acked < messages_sent && timeout-- > 0) {
        lwip_poll();
        Sleep(100);
    }

    printf("\nPerformance Summary:\n");
    printf("  Messages sent: %d\n", messages_sent);
    printf("  Messages ACKed: %d\n", messages_acked);
    printf("  Total time: %lu ms\n", elapsed);
    printf("  Average: %.2f ms/message\n", (double)elapsed / messages_sent);
    printf("  Throughput: %.2f messages/second\n", 
           messages_sent * 1000.0 / elapsed);

    // Cleanup
    lwip_ssl_disconnect_persistent("conn2");
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(100);
    }

    lwip_close_connection("conn2");
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();
}

/**
 * Example 3: Error handling and retry logic
 */
void example_error_handling() {
    printf("\n=== Example 3: Error Handling ===\n");

    // Initialize
    init_lwip_lock();
    lwip_init_stack_global();
    lwip_ssl_init_global();

    lwip_create_connection("conn3",
        "192.168.1.10", "255.255.255.0", "192.168.1.1",
        udp_send_callback, NULL);

    // Connect
    handshake_done = 0;
    lwip_ssl_connect_persistent("conn3", "10.0.0.100", 443, "api.example.com",
        on_handshake_complete, on_data_received, on_message_sent);

    while (handshake_done == 0) {
        lwip_poll();
        Sleep(50);
    }

    if (handshake_done < 0) {
        printf("Failed to connect\n");
        goto cleanup;
    }

    // Send with comprehensive error handling
    const char* data = "Important message";
    char msg_id[] = "critical_001";

    printf("Sending critical message...\n");

    int result = lwip_ssl_send_persistent("conn3",
        (const uint8_t*)data, strlen(data), msg_id);

    if (result == 0) {
        printf("? Message sent successfully\n");
    } else if (result == -2) {
        printf("? Buffer full, implementing retry logic...\n");

        // Retry with exponential backoff
        int retries = 0;
        const int max_retries = 5;
        int delay = 50;

        while (retries < max_retries) {
            printf("  Retry %d/%d after %d ms...\n", 
                   retries + 1, max_retries, delay);

            lwip_poll();  // Process network to free buffers
            Sleep(delay);

            result = lwip_ssl_send_persistent("conn3",
                (const uint8_t*)data, strlen(data), msg_id);

            if (result == 0) {
                printf("? Message sent on retry %d\n", retries + 1);
                break;
            } else if (result == -1) {
                printf("? Fatal error - connection broken\n");
                break;
            }

            retries++;
            delay *= 2;  // Exponential backoff
        }

        if (retries >= max_retries && result != 0) {
            printf("? Failed after %d retries\n", max_retries);
        }
    } else if (result == -1) {
        printf("? Fatal error - connection broken\n");
        // In production: log error, reconnect, or failover
    }

    // Wait for ACK
    if (result == 0) {
        printf("\nWaiting for acknowledgment...\n");
        int ack_received = 0;
        for (int i = 0; i < 100 && !ack_received; i++) {
            lwip_poll();
            Sleep(100);
            // Check if our message was ACKed (would be in callback)
        }
    }

cleanup:
    // Cleanup
    printf("\nCleaning up...\n");
    lwip_ssl_disconnect_persistent("conn3");
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(100);
    }

    lwip_close_connection("conn3");
    lwip_ssl_cleanup_global();
    cleanup_lwip_lock();
    printf("Done!\n");
}

/**
 * Main entry point
 */
int main() {
    printf("SSL Persistent Connection Examples\n");
    printf("===================================\n");

    // Run examples
    example_basic_persistent_ssl();
    Sleep(1000);

    example_high_throughput();
    Sleep(1000);

    example_error_handling();

    printf("\nAll examples completed!\n");
    return 0;
}
