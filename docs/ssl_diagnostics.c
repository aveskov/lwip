// SSL ACK Queue Diagnostic Functions
// Add these to lwip_wrapper_ssl.cpp and lwip_wrapper_ssl.h

// Get number of pending ACK callbacks in queue
__declspec(dllexport) int lwip_ssl_get_pending_ack_count(const char* id) {
    if (!id) return -1;
    
    ssl_connection_entry_t* conn = find_ssl_connection(id);
    if (!conn) return -1;
    
    ssl_lock();
    int count = 0;
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        count++;
        entry = entry->next;
    }
    ssl_unlock();
    
    ssl_conn_unref(conn);
    return count;
}

// Get total bytes waiting for ACK
__declspec(dllexport) int lwip_ssl_get_pending_ack_bytes(const char* id) {
    if (!id) return -1;
    
    ssl_connection_entry_t* conn = find_ssl_connection(id);
    if (!conn) return -1;
    
    ssl_lock();
    int total_bytes = 0;
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        total_bytes += entry->bytes_sent;
        entry = entry->next;
    }
    ssl_unlock();
    
    ssl_conn_unref(conn);
    return total_bytes;
}

// Get statistics about connection
typedef struct {
    int pending_ack_count;
    int pending_ack_bytes;
    int total_messages_sent;
    int tcp_buffer_available;
    ssl_connection_state_t state;
    ssl_connection_mode_t mode;
} ssl_connection_stats_t;

__declspec(dllexport) int lwip_ssl_get_connection_stats(const char* id, ssl_connection_stats_t* stats) {
    if (!id || !stats) return -1;
    
    memset(stats, 0, sizeof(ssl_connection_stats_t));
    
    ssl_connection_entry_t* conn = find_ssl_connection(id);
    if (!conn) return -1;
    
    ssl_lock();
    
    // Count pending ACKs
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        stats->pending_ack_count++;
        stats->pending_ack_bytes += entry->bytes_sent;
        entry = entry->next;
    }
    
    stats->total_messages_sent = conn->message_count;
    stats->state = conn->state;
    stats->mode = conn->mode;
    
    // Get TCP buffer available
    if (conn->pcb) {
        lwip_lock();
        stats->tcp_buffer_available = tcp_sndbuf(conn->pcb);
        lwip_unlock();
    }
    
    ssl_unlock();
    
    ssl_conn_unref(conn);
    return 0;
}

// Diagnostic: Print ACK queue state
__declspec(dllexport) void lwip_ssl_print_ack_queue(const char* id) {
    if (!id) return;
    
    ssl_connection_entry_t* conn = find_ssl_connection(id);
    if (!conn) {
        printf("SSL connection '%s' not found\n", id);
        return;
    }
    
    ssl_lock();
    
    printf("=== SSL ACK Queue for '%s' ===\n", id);
    printf("Connection state: %d, mode: %d\n", conn->state, conn->mode);
    printf("Total messages sent: %d\n", conn->message_count);
    
    int count = 0;
    int total_bytes = 0;
    pending_ssl_ack_entry_t* entry = conn->pending_acks_head;
    
    while (entry) {
        count++;
        total_bytes += entry->bytes_sent;
        printf("  #%d: msg_id='%s', bytes=%d\n", 
               count, entry->message_id ? entry->message_id : "NULL", entry->bytes_sent);
        entry = entry->next;
    }
    
    printf("Total pending: %d messages, %d bytes\n", count, total_bytes);
    
    if (conn->pcb) {
        lwip_lock();
        printf("TCP send buffer available: %d bytes\n", tcp_sndbuf(conn->pcb));
        lwip_unlock();
    }
    
    ssl_unlock();
    
    ssl_conn_unref(conn);
    printf("=======================\n");
}

// Example usage in your application:
void monitor_ssl_connection(const char* id) {
    ssl_connection_stats_t stats;
    
    if (lwip_ssl_get_connection_stats(id, &stats) == 0) {
        if (stats.pending_ack_count > 10) {
            printf("WARNING: High ACK queue (%d messages, %d bytes)\n",
                   stats.pending_ack_count, stats.pending_ack_bytes);
            printf("TCP buffer: %d bytes available\n", stats.tcp_buffer_available);
            
            // Consider slowing down sends
            lwip_poll();  // Process ACKs
            Sleep(50);
        }
        
        if (stats.tcp_buffer_available < 512) {
            printf("WARNING: Low TCP buffer (%d bytes)\n", stats.tcp_buffer_available);
            // Wait for buffer to drain
            lwip_poll();
            Sleep(20);
        }
    }
}

// Rate-limited send with diagnostics
int send_with_monitoring(const char* id, const uint8_t* data, int len, const char* msg_id) {
    ssl_connection_stats_t stats;
    
    // Check state before sending
    if (lwip_ssl_get_connection_stats(id, &stats) != 0) {
        return -1;
    }
    
    // Apply backpressure if queue is too large
    const int MAX_PENDING = 15;
    if (stats.pending_ack_count >= MAX_PENDING) {
        printf("ACK queue full (%d), waiting...\n", stats.pending_ack_count);
        
        // Wait for queue to drain
        for (int i = 0; i < 50; i++) {
            lwip_poll();
            Sleep(20);
            
            if (lwip_ssl_get_pending_ack_count(id) < MAX_PENDING) {
                break;
            }
        }
        
        // Check again
        if (lwip_ssl_get_pending_ack_count(id) >= MAX_PENDING) {
            printf("ERROR: ACK queue still full after waiting\n");
            return -3;  // Queue full
        }
    }
    
    // Check TCP buffer
    if (stats.tcp_buffer_available < len) {
        printf("TCP buffer low (%d < %d), waiting...\n", stats.tcp_buffer_available, len);
        
        for (int i = 0; i < 20; i++) {
            lwip_poll();
            Sleep(10);
            
            int avail = lwip_tcp_get_send_buffer_available(id);
            if (avail >= len) {
                break;
            }
        }
    }
    
    // Send
    return lwip_ssl_send_persistent(id, data, len, msg_id);
}
