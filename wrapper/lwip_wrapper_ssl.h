#ifndef LWIP_WRAPPER_SSL_H
#define LWIP_WRAPPER_SSL_H

#include "lwip_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ssl_handshake_complete_callback_t)(int success);
typedef void (*ssl_data_received_callback_t)(const uint8_t* data, int len);
typedef void (*ssl_send_complete_callback_t)(void);
typedef void (*ssl_send_ack_complete_callback_t)(const char* message_id);  // Called when specific message is sent

// Global initialization
__declspec(dllexport) void lwip_ssl_init_global(void);
__declspec(dllexport) void lwip_ssl_cleanup_global(void);

// Non-persistent SSL connection (single send, then close)
__declspec(dllexport) int lwip_ssl_connect(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,     
	                 ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_complete_callback_t ssl_complete_cb);
__declspec(dllexport) int lwip_ssl_send_data(const char* id, const uint8_t* data, int len);
__declspec(dllexport) void lwip_ssl_close_connection(const char* id);

// Persistent SSL connection (multiple sends over same connection)
__declspec(dllexport) int lwip_ssl_connect_persistent(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,
                     ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_ack_complete_callback_t ack_cb);
__declspec(dllexport) int lwip_ssl_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id);
__declspec(dllexport) void lwip_ssl_disconnect_persistent(const char* id);

// Helper function to check if SSL connection is ready
__declspec(dllexport) int lwip_ssl_is_connected(const char* id);

// Diagnostic functions for ACK queue monitoring
__declspec(dllexport) int lwip_ssl_get_pending_ack_count(const char* id);

#ifdef __cplusplus
}
#endif

#endif