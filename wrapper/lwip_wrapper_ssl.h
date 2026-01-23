#ifndef LWIP_WRAPPER_SSL_H
#define LWIP_WRAPPER_SSL_H

#include "lwip_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ssl_handshake_complete_callback_t)(int success);
typedef void (*ssl_data_received_callback_t)(const uint8_t* data, int len);
typedef void (*ssl_send_complete_callback_t)(void);  // Called immediately when SSL_write succeeds
typedef void (*ssl_send_ack_complete_callback_t)(const char* message_id);  // Called later when TCP ACKs message

// Global initialization
__declspec(dllexport) void lwip_ssl_init_global(void);
__declspec(dllexport) void lwip_ssl_cleanup_global(void);

// Non-persistent SSL connection (single send, then close)
// NOTE: send_complete_cb is optional (can be NULL) - called after SSL_write succeeds
// Use lwip_ssl_close_connection() to close this type of connection
__declspec(dllexport) int lwip_ssl_connect(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,     
	                 ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_complete_callback_t send_complete_cb);  // Optional: can be NULL
__declspec(dllexport) int lwip_ssl_send_data(const char* id, const uint8_t* data, int len);

// Close non-persistent SSL connection
// Use this ONLY for connections created with lwip_ssl_connect()
// For persistent connections, use lwip_ssl_disconnect_persistent() instead
__declspec(dllexport) void lwip_ssl_close_connection(const char* id);

// Persistent SSL connection (multiple sends over same connection)
__declspec(dllexport) int lwip_ssl_connect_persistent(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,
                     ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_send_ack_complete_callback_t ack_cb);       // ACK confirmation
__declspec(dllexport) int lwip_ssl_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id);

// Close persistent SSL connection
__declspec(dllexport) void lwip_ssl_disconnect_persistent(const char* id);

__declspec(dllexport) int lwip_ssl_is_connected(const char* id);
__declspec(dllexport) int lwip_ssl_get_send_buffer_available(const char* id);

// Diagnostic functions for ACK queue monitoring
__declspec(dllexport) int lwip_ssl_get_pending_ack_count(const char* id);

// Optimized batch send with TCP_WRITE_FLAG_MORE for maximum throughput
// Sends multiple messages and flushes only once at the end
// Returns: number of messages successfully sent (0 to batch_size)
__declspec(dllexport) int lwip_ssl_send_batch_optimized(const char* id, 
                                                        const uint8_t** data_array, 
                                                        const int* len_array, 
                                                        const char** message_ids, 
                                                        int batch_size);

// Nagle's algorithm control for throughput tuning
// Enable Nagle: Better for high-latency networks, batches small packets
__declspec(dllexport) int lwip_ssl_enable_nagle(const char* id);

// Disable Nagle: Better for low-latency (default for persistent connections)
__declspec(dllexport) int lwip_ssl_disable_nagle(const char* id);

// TCP Keep-Alive for SSL connections
// Enable keep-alive to prevent persistent SSL connections from timing out
// idle_secs: seconds of inactivity before first probe (default: 120s recommended for SSL)
// interval_secs: seconds between probes (default: 30s)
// count: number of probes before giving up (default: 3)
__declspec(dllexport) int lwip_ssl_set_keepalive(const char* id, int enable, int idle_secs, int interval_secs, int count);

#ifdef __cplusplus
}
#endif

#endif