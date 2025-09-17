#ifndef LWIP_WRAPPER_H
#define LWIP_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

    // Forward declarations
    typedef struct connection_entry connection_entry_t;

    // Callback function types
    typedef void (*udp_send_callback_t)(uint8_t* data, int len);
    typedef void (*tcp_send_complete_callback_t)(void);

    // Core LwIP functions
    void init_lwip_lock(void);
    void cleanup_lwip_lock(void);
    void lwip_init_stack_global(void);
    void lwip_poll(void);

    // Connection management
    int lwip_create_connection(const char* id,
        const char* src_ip_str,
        const char* netmask_str,
        const char* gw_str,
        udp_send_callback_t udp_cb,
        tcp_send_complete_callback_t tcp_complete_cb);

    int lwip_connect(const char* id, const char* dest_ip_str, int port, const char* message);
    void lwip_close_connection(const char* id);
    void lwip_process_packet(const char* id, uint8_t* data, int len);

    // Helper functions for SSL wrapper    
    connection_entry_t* find_connection(const char* id);
    void conn_ref(connection_entry_t* conn);
    void conn_unref(connection_entry_t* conn);
    void lwip_lock(void);
    void lwip_unlock(void);    

    // Custom routing
    void* ip4_route_custom(const void* src, const void* dest);

#ifdef __cplusplus
}
#endif

#endif // LWIP_WRAPPER_H