#ifndef LWIP_WRAPPER_SSL_H
#define LWIP_WRAPPER_SSL_H

#include "lwip_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ssl_handshake_complete_callback_t)(int success);
typedef void (*ssl_data_received_callback_t)(const uint8_t* data, int len);
typedef void (*ssl_send_complete_callback_t)(void);

__declspec(dllexport) void lwip_ssl_init_global(void);
__declspec(dllexport) void lwip_ssl_cleanup_global(void);
__declspec(dllexport) int lwip_ssl_connect(const char* id,
                     const char* dest_ip_str, 
                     int port,
                     const char* hostname,     
	                 ssl_handshake_complete_callback_t handshake_complete_cb,
                     ssl_data_received_callback_t data_received_cb,
                     ssl_send_complete_callback_t ssl_complete_cb);
__declspec(dllexport) int lwip_ssl_send_data(const char* id, const uint8_t* data, int len);
__declspec(dllexport) void lwip_ssl_close_connection(const char* id);

#ifdef __cplusplus
}
#endif

#endif