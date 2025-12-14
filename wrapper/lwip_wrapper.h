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
    typedef void (*send_complete_callback_t)(void);
    typedef void (*send_ack_complete_callback_t)(const char* message_id);  // Called when specific message is ACKed

    // Core LwIP functions
    void init_lwip_lock(void);
    void cleanup_lwip_lock(void);
    void lwip_init_stack_global(void);
    void lwip_cleanup_stack_global(void);  // Cleanup all resources on application shutdown
    void lwip_poll(void);

    // Connection management
    int lwip_create_connection(const char* id,
        const char* src_ip_str,
        const char* netmask_str,
        const char* gw_str,
        udp_send_callback_t udp_cb,
        send_complete_callback_t send_complete_cb);

    int lwip_tcp_send(const char* id, const char* dest_ip_str, int port, const char* message);
    
    // Persistent TCP connection with message ID tracking
    int lwip_tcp_connect_persistent(const char* id, const char* dest_ip_str, int port, send_ack_complete_callback_t ack_cb);
    int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id);
    void lwip_tcp_disconnect_persistent(const char* id);
    
    int lwip_tcp_set_nodelay(const char* id, int enable);  // Control Nagle's algorithm
    int lwip_tcp_get_send_buffer_available(const char* id);  // Check available send buffer    
    int lwip_tcp_get_pending_ack_count(const char* id);
    
    // TCP Keep-Alive functions to prevent connection from becoming stale
    // Enable/disable TCP keep-alive with custom intervals
    // idle_secs: seconds of inactivity before first keep-alive probe (default: 7200s = 2 hours)
    // interval_secs: seconds between keep-alive probes (default: 75s)
    // count: number of probes before giving up (default: 9)
    int lwip_tcp_set_keepalive(const char* id, int enable, int idle_secs, int interval_secs, int count);
    
    int lwip_udp_send(const char* id, const char* dest_ip_str, int port, const uint8_t* data, int len);
    void lwip_close_connection(const char* id);
    void lwip_process_packet(const char* id, const uint8_t* data, int len);
    
    // Batch TCP send with TCP_WRITE_FLAG_MORE optimization
    // Sends multiple messages over persistent TCP connection with minimal overhead
    // All messages are buffered and sent in one tcp_output() call
    // Returns: number of messages successfully sent (0 to batch_size)
    // Note: Connection must be established with lwip_tcp_connect_persistent() first
    int lwip_tcp_send_batch_optimized(const char* id,
                                       const char* dest_ip_str,
                                       int port,
                                       const uint8_t** data_array,
                                       const int* len_array,
                                       const char** message_ids,
                                       int batch_size);
    
    // Batch UDP send optimization
    // Sends multiple UDP datagrams to the same destination with minimal overhead
    // UDP is connectionless but we still optimize by reusing the PCB and minimizing allocations
    // Returns: number of messages successfully sent (0 to batch_size)
    int lwip_udp_send_batch_optimized(const char* id,
                                       const char* dest_ip_str,
                                       int port,
                                       const uint8_t** data_array,
                                       const int* len_array,
                                       int batch_size);

    // Helper functions for SSL wrapper    
    connection_entry_t* find_connection(const char* id);
    void conn_ref(connection_entry_t* conn);
    void conn_unref(connection_entry_t* conn);
    void lwip_lock(void);
    void lwip_unlock(void);    
    const ip_addr_t* get_connection_src_ip(connection_entry_t* conn);
    struct netif* get_connection_netif(connection_entry_t* conn);

    // Custom routing
    void* ip4_route_custom(const void* src, const void* dest);

#ifdef __cplusplus
}
#endif

#endif // LWIP_WRAPPER_H#endif // LWIP_WRAPPER_H