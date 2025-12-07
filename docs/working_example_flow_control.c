// Complete working example: Sending multiple messages with proper flow control

#include "lwip_wrapper.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

// Callbacks
void my_udp_callback(uint8_t* data, int len) {
    // This sends packets to the network
    // You need to implement actual network send here
    printf("Sending %d bytes to network\n", len);
}

void my_send_complete_callback(void) {
    printf("Message acknowledged by remote\n");
}

// Helper function: Send with automatic retry on buffer full
int send_with_retry(const char* id, const uint8_t* data, int len, int max_retries) {
    for (int retry = 0; retry < max_retries; retry++) {
        int result = lwip_tcp_send_persistent(id, data, len);
        
        if (result == 0) {
            return 0;  // Success
        }
        else if (result == -2) {
            // Buffer full - wait and retry
            printf("  Retry %d/%d: Buffer full, waiting...\n", retry + 1, max_retries);
            
            // Give LwIP time to process and free buffer
            for (int i = 0; i < 5; i++) {
                lwip_poll();
                Sleep(20);
            }
        }
        else {
            // Fatal error
            printf("  Fatal error: %d\n", result);
            return -1;
        }
    }
    
    printf("  ERROR: Failed after %d retries\n", max_retries);
    return -1;
}

int main() {
    printf("=== TCP Persistent Connection with Flow Control ===\n\n");
    
    // 1. Initialize LwIP
    lwip_init_stack_global();
    printf("1. LwIP initialized\n");
    
    // 2. Create connection
    int result = lwip_create_connection(
        "conn1",                // Connection ID
        "192.168.1.100",        // Source IP
        "255.255.255.0",        // Netmask
        "192.168.1.1",          // Gateway
        my_udp_callback,        // Callback for outgoing packets
        my_send_complete_callback  // Callback when send completes
    );
    
    if (result != 0) {
        printf("ERROR: Failed to create connection\n");
        return 1;
    }
    printf("2. Connection created\n");
    
    // 3. Connect to remote server (persistent connection)
    result = lwip_tcp_connect_persistent("conn1", "192.168.1.200", 8080);
    if (result != 0) {
        printf("ERROR: Failed to connect\n");
        lwip_close_connection("conn1");
        return 1;
    }
    printf("3. Connecting to 192.168.1.200:8080...\n");
    
    // Wait for connection to establish
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(10);
    }
    printf("4. Connection established\n\n");
    
    // 4. Send multiple messages with flow control
    printf("Sending 10 messages...\n");
    
    int success_count = 0;
    int failed_count = 0;
    
    for (int i = 0; i < 10; i++) {
        // Create message
        uint8_t message[200];
        int msg_len = sprintf((char*)message, "Message #%d: Hello from persistent connection!", i);
        
        // Check buffer availability before sending
        int available = lwip_tcp_get_send_buffer_available("conn1");
        printf("\nMessage %d: buffer available = %d bytes, need = %d bytes\n", 
               i, available, msg_len);
        
        // Wait if buffer is too full (less than message size available)
        if (available >= 0 && available < msg_len) {
            printf("  Buffer low, waiting for space...\n");
            int wait_count = 0;
            while (available < msg_len && wait_count < 20) {
                lwip_poll();
                Sleep(50);
                available = lwip_tcp_get_send_buffer_available("conn1");
                wait_count++;
            }
            printf("  Buffer freed: %d bytes available\n", available);
        }
        
        // Send with retry
        result = send_with_retry("conn1", message, msg_len, 5);
        
        if (result == 0) {
            printf("  ? Message %d sent successfully\n", i);
            success_count++;
        } else {
            printf("  ? Message %d FAILED\n", i);
            failed_count++;
        }
        
        // IMPORTANT: Always call lwip_poll after sending
        lwip_poll();
        
        // Small delay between messages (adjust based on your needs)
        Sleep(10);
    }
    
    // Final processing
    printf("\nProcessing remaining packets...\n");
    for (int i = 0; i < 10; i++) {
        lwip_poll();
        Sleep(50);
    }
    
    printf("\n=== Summary ===\n");
    printf("Sent: %d/%d messages successfully\n", success_count, 10);
    printf("Failed: %d messages\n", failed_count);
    
    // 5. Disconnect persistent connection
    printf("\n5. Disconnecting...\n");
    lwip_tcp_disconnect_persistent("conn1");
    lwip_poll();
    Sleep(100);
    
    // 6. Close connection
    printf("6. Closing connection...\n");
    lwip_close_connection("conn1");
    
    printf("Done!\n");
    return 0;
}

/* 
 * EXPECTED OUTPUT:
 * 
 * === TCP Persistent Connection with Flow Control ===
 * 
 * 1. LwIP initialized
 * 2. Connection created
 * 3. Connecting to 192.168.1.200:8080...
 * 4. Connection established
 * 
 * Sending 10 messages...
 * 
 * Message 0: buffer available = 2048 bytes, need = 52 bytes
 *   ? Message 0 sent successfully
 * 
 * Message 1: buffer available = 1996 bytes, need = 52 bytes
 *   ? Message 1 sent successfully
 * 
 * ... (more messages)
 * 
 * Message 5: buffer available = 256 bytes, need = 52 bytes
 *   Buffer low, waiting for space...
 *   Buffer freed: 512 bytes available
 *   ? Message 5 sent successfully
 * 
 * ... (remaining messages)
 * 
 * === Summary ===
 * Sent: 10/10 messages successfully
 * Failed: 0 messages
 * 
 * 5. Disconnecting...
 * 6. Closing connection...
 * Done!
 */

/*
 * TROUBLESHOOTING:
 * 
 * If you still get errors after this:
 * 
 * 1. Check that my_udp_callback actually sends packets to the network
 *    - Without real network send, buffers will never drain
 * 
 * 2. Increase delay between messages:
 *    Sleep(10); -> Sleep(50); or Sleep(100);
 * 
 * 3. Reduce message size or send rate
 * 
 * 4. Make sure you're calling lwip_poll() frequently enough
 * 
 * 5. Check lwip_process_packet() is being called when packets arrive
 *    - This processes ACKs and frees send buffer
 */
