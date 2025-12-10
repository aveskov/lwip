#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/etharp.h"

#include "lwip_wrapper.h"

// Message tracking structure for ACK callbacks
typedef struct pending_ack_entry {
    char* message_id;                         // User-provided message identifier (string)
    u16_t bytes_sent;                         // Number of bytes in this message
    struct pending_ack_entry* next;           // Next pending ACK
} pending_ack_entry_t;

typedef struct connection_entry {
    char* id;
    struct netif netif;
    struct tcp_pcb* pcb;
    struct udp_pcb* udp_pcb;
    ip4_addr_t src_ip;
    char* message;
    udp_send_callback_t udp_callback;
    send_complete_callback_t send_complete_callback;
    send_ack_complete_callback_t send_ack_complete_callback;  // New: ACK callback with message ID
    struct connection_entry* next;
    volatile int ref_count;  // Reference counting for safe cleanup
    int persistent_mode;  // Flag for persistent TCP connections
    
    // Message tracking for ACK callbacks
    pending_ack_entry_t* pending_acks_head;   // Head of pending ACK queue
    pending_ack_entry_t* pending_acks_tail;   // Tail of pending ACK queue
} connection_entry_t;

static connection_entry_t* connection_list = NULL;
static CRITICAL_SECTION lwip_lock_var;
static volatile int lwip_initialized = 0;

void lwip_lock(void) {
    if (lwip_initialized) {
        EnterCriticalSection(&lwip_lock_var);
    }
}

void lwip_unlock(void) {
    if (lwip_initialized) {
        LeaveCriticalSection(&lwip_lock_var);
    }
}

void init_lwip_lock() {
    if (!lwip_initialized) {
        InitializeCriticalSection(&lwip_lock_var);
        lwip_initialized = 1;
    }
}

void cleanup_lwip_lock() {
    if (lwip_initialized) {
        DeleteCriticalSection(&lwip_lock_var);
        lwip_initialized = 0;
    }
}

// Helper function to safely increment reference count
void conn_ref(connection_entry_t* conn) {
    if (conn) {
        InterlockedIncrement(&conn->ref_count);
    }
}

// Helper function to safely decrement reference count and cleanup if needed
void conn_unref(connection_entry_t* conn) {
    if (conn && InterlockedDecrement(&conn->ref_count) == 0) {
        // Safe to cleanup
        if (conn->id) free(conn->id);
        if (conn->message) free(conn->message);
        
        // Clean up pending ACK queue to prevent memory leaks
        // This can happen when connection is freed via error callbacks
        // or lwip_cleanup_all_connections() before ACKs are received
        while (conn->pending_acks_head) {
            pending_ack_entry_t* next = conn->pending_acks_head->next;
            if (conn->pending_acks_head->message_id) {
                free(conn->pending_acks_head->message_id);
            }
            free(conn->pending_acks_head);
            conn->pending_acks_head = next;
        }
        conn->pending_acks_tail = NULL;
        
        free(conn);
    }
}

const ip_addr_t* get_connection_src_ip(connection_entry_t* conn) {
    if (conn) {
        return (const ip_addr_t*)&conn->src_ip;
    }
    return NULL;
}

struct netif* get_connection_netif(connection_entry_t* conn) {
    if (conn) {
        return &conn->netif;
    }
    return NULL;
}

static err_t output_cb(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
    if (!netif || !netif->state ||!p) {
        printf("ERROR: Invalid parameters in output_cb\n");
        return ERR_VAL;
    }

    connection_entry_t* conn = (connection_entry_t*)netif->state;
    if (!conn || !conn->udp_callback) {
        printf("ERROR: Invalid connection or callback in output_cb\n");
        return ERR_VAL;
    }

    uint8_t* buf = malloc(p->tot_len);
    if (!buf) {
        printf("ERROR: Memory allocation failed in output_cb\n");
        return ERR_MEM;
    }

    pbuf_copy_partial(p, buf, p->tot_len, 0);
    conn->udp_callback(buf, p->tot_len);
    free(buf);

    return ERR_OK;
}

static err_t linkoutput_cb(struct netif* netif, struct pbuf* p) {
    return output_cb(netif, p, NULL);
}

static void input_cb(connection_entry_t* conn, const uint8_t* data, int len) {
    if (!conn || !data || len <= 0) {
        printf("ERROR: Invalid parameters in input_cb\n");
        return;
    }

    struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p) {
        printf("ERROR: Failed to allocate pbuf in input_cb\n");
        return;
    }

    if (pbuf_take(p, data, len) != ERR_OK) {
        printf("ERROR: Failed to copy data to pbuf\n");
        pbuf_free(p);
        return;
    }

    lwip_lock();
    if (netif_is_up(&conn->netif)) {
        netif_input(p, &conn->netif);
    }
    else {
        pbuf_free(p);
    }
    lwip_unlock();
}


// Sent callback for persistent connections - called when data is ACKed
static err_t on_tcp_sent_persistent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    connection_entry_t* conn = (connection_entry_t*)arg;
    
    if (!conn) return ERR_ARG;

    // Process ACK queue to match ACKed bytes with message IDs
    lwip_lock();
    
    u16_t bytes_acked = len;
    
    while (bytes_acked > 0 && conn->pending_acks_head != NULL) {
        pending_ack_entry_t* ack_entry = conn->pending_acks_head;
        
        if (bytes_acked >= ack_entry->bytes_sent) {
            // This message is fully ACKed
            bytes_acked -= ack_entry->bytes_sent;
            
            // Remove from queue
            conn->pending_acks_head = ack_entry->next;
            if (conn->pending_acks_head == NULL) {
                conn->pending_acks_tail = NULL;
            }
            
            // Copy message ID and callback before freeing entry
            char* message_id = ack_entry->message_id;
            send_ack_complete_callback_t callback = conn->send_ack_complete_callback;
            
            // Don't free message_id yet - callback might need it
            free(ack_entry);  // Free the entry structure
            
            // Call ACK callback outside the lock
            lwip_unlock();
            if (callback && message_id) {
                callback(message_id);
            }
            // Now safe to free message ID
            if (message_id) {
                free(message_id);
            }
            lwip_lock();
        } else {
            // Partial ACK - reduce bytes_sent in this entry
            ack_entry->bytes_sent -= bytes_acked;
            bytes_acked = 0;
        }
    }
    
    lwip_unlock();

    return ERR_OK;
}

static err_t on_tcp_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    connection_entry_t* conn = (connection_entry_t*)arg;
    if (!conn) return ERR_ARG;    

    if (conn->send_complete_callback) {
        conn->send_complete_callback();
    }

    lwip_lock();
    if (tpcb && conn->pcb == tpcb) {
        tcp_arg(tpcb, NULL);
        tcp_sent(tpcb, NULL);
        tcp_recv(tpcb, NULL);
        tcp_err(tpcb, NULL);
        
        // Check if netif is still up before closing
        if (netif_is_up(&conn->netif)) {
            err_t close_err = tcp_close(tpcb);
            if (close_err != ERR_OK) {
                // If close fails, abort the connection
                printf("tcp_close failed: %d, aborting\n", close_err);
                tcp_abort(tpcb);
            }
        } else {
            // Netif is down, abort instead of close to avoid routing issues
            tcp_abort(tpcb);
        }
        conn->pcb = NULL;
    }
    lwip_unlock();

    conn_unref(conn);  // Release reference
    return ERR_OK;
}

static err_t tcp_connected(void* arg, struct tcp_pcb* tpcb, err_t err) {
    connection_entry_t* conn = (connection_entry_t*)arg;       
    if (!conn || err != ERR_OK) {
        if (conn) conn_unref(conn);
        return err;
    }

    lwip_lock();
    
    // Set sent callback BEFORE any sends
    if (conn->persistent_mode) {
        // Persistent mode: use callback that doesn't close connection
        tcp_sent(tpcb, on_tcp_sent_persistent);
    }
        
    // Disable Nagle's algorithm for reduced latency
    tcp_nagle_disable(tpcb);
    
    if (conn->message && strlen(conn->message) > 0) {
        err_t wr = tcp_write(tpcb, conn->message, strlen(conn->message), TCP_WRITE_FLAG_COPY);
        if (wr == ERR_OK) {
            tcp_output(tpcb);
            
            if (!conn->persistent_mode) {
                // Non-persistent mode: close after send
                tcp_sent(tpcb, on_tcp_sent);
                tcp_arg(tpcb, conn);
                conn_ref(conn);  // Add reference for sent callback
            } else {
                // Persistent mode: callback already set above
                if (conn->send_complete_callback) {
                    conn->send_complete_callback();
                }
            }
        }
        else {
            printf("tcp_write failed: %d\n", wr);
            // Clean up on write failure
            tcp_arg(tpcb, NULL);
            tcp_sent(tpcb, NULL);
            tcp_recv(tpcb, NULL);
            tcp_err(tpcb, NULL);
            tcp_abort(tpcb);
            conn->pcb = NULL;
            lwip_unlock();
            conn_unref(conn);
            return ERR_ABRT;
        }
        free(conn->message);
        conn->message = NULL;
    }
    else {
        if (!conn->persistent_mode) {
            // No message to send, close immediately
            tcp_arg(tpcb, NULL);
            tcp_sent(tpcb, NULL);
            tcp_recv(tpcb, NULL);
            tcp_err(tpcb, NULL);
            tcp_close(tpcb);
            conn->pcb = NULL;
            lwip_unlock();
            conn_unref(conn);
            return ERR_OK;
        }
        // Persistent mode: keep connection open even with no initial message
    }
    lwip_unlock();

    return ERR_OK;
}

static err_t tcp_recv_cb(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
    connection_entry_t* conn = (connection_entry_t*)arg;

    if (!p) {
        printf("Remote closed the connection.\n");
        lwip_lock();
        if (tpcb && conn && conn->pcb == tpcb) {
            tcp_close(tpcb);
            conn->pcb = NULL;
        }
        lwip_unlock();
        if (conn) conn_unref(conn);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        if (conn) conn_unref(conn);
        return err;
    }    

    lwip_lock();
    if (tpcb) {
        tcp_recved(tpcb, p->len);
    }
    lwip_unlock();

    pbuf_free(p);
    return ERR_OK;
}

static void on_tcp_error(void* arg, err_t err) {
    connection_entry_t* conn = (connection_entry_t*)arg;
    printf("TCP error: %d\n", err);

    if (conn) {
        lwip_lock();
        if (conn->message) {
            free(conn->message);
            conn->message = NULL;
        }
        conn->pcb = NULL;  // PCB is already freed by LwIP on error
        conn->persistent_mode = 0;  // Clear persistent mode flag
        lwip_unlock();
        conn_unref(conn);
    }
}

static void udp_recv_cb(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {   
    pbuf_free(p);
}

static err_t netif_init_cb(struct netif* netif) {
    if (!netif) return ERR_ARG;

    netif->output = output_cb;
    netif->linkoutput = linkoutput_cb;
    netif->mtu = 1280;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;
    return ERR_OK;
}

static connection_entry_t* find_connection_locked(const char* id) {
    if (!id) return NULL;

    connection_entry_t* conn = connection_list;
    while (conn) {
        if (conn->id && strcmp(conn->id, id) == 0) {
            return conn;
        }
        conn = conn->next;
    }
    return NULL;
}

connection_entry_t* find_connection(const char* id) {
    lwip_lock();
    connection_entry_t* conn = find_connection_locked(id);
    if (conn) {
        conn_ref(conn);  // Add reference before returning
    }
    lwip_unlock();

    if (!conn) {
       printf("Connection '%s' not found.\n", id ? id : "NULL");
    }

    return conn;
}

int lwip_create_connection(const char* id,
    const char* src_ip_str,
    const char* netmask_str,
    const char* gw_str,
    udp_send_callback_t udp_cb,
    send_complete_callback_t send_complete_cb) {

    if (!id || !src_ip_str || !netmask_str || !gw_str) {
        printf("ERROR: Invalid parameters for connection creation\n");
        return -1;
    }

    ip4_addr_t src_ip, netmask, gw;
    if (!ipaddr_aton(src_ip_str, &src_ip) ||
        !ipaddr_aton(netmask_str, &netmask) ||
        !ipaddr_aton(gw_str, &gw)) {
        printf("ERROR: Invalid IP address format\n");
        return -1;
    }

    lwip_lock();
   
    if (find_connection_locked(id)) {
        lwip_unlock();
        printf("ERROR: Connection '%s' already exists\n", id);
        return -1;
    }

    connection_entry_t* conn = (connection_entry_t*)calloc(1, sizeof(connection_entry_t));
    if (!conn) {
        lwip_unlock();
        printf("ERROR: Memory allocation failed\n");
        return -1;
    }

    conn->id = _strdup(id);
    if (!conn->id) {
        free(conn);
        lwip_unlock();
        printf("ERROR: Failed to duplicate connection ID\n");
        return -1;
    }

    conn->src_ip = src_ip;
    conn->udp_callback = udp_cb;
    conn->send_complete_callback = send_complete_cb;
    conn->send_ack_complete_callback = NULL;  // Initialize ACK callback to NULL
    conn->netif.state = conn;
    conn->ref_count = 1;  // Initial reference
    conn->pending_acks_head = NULL;  // Initialize ACK queue
    conn->pending_acks_tail = NULL;

    if (!netif_add(&conn->netif, &src_ip, &netmask, &gw, conn, netif_init_cb, netif_input)) {
        free(conn->id);
        free(conn);
        lwip_unlock();
        printf("ERROR: Failed to add network interface\n");
        return -1;
    }

    netif_set_up(&conn->netif);
    conn->next = connection_list;
    connection_list = conn;

    lwip_unlock();
    return 0;
}

void lwip_poll() {
    if (!lwip_initialized) return;

    lwip_lock();
    sys_check_timeouts();
    lwip_unlock();
}

void lwip_init_stack_global() {
    init_lwip_lock();
    lwip_init();
    netif_set_default(NULL);
}

void lwip_process_packet(const char* id, const uint8_t* data, int len) {
    if (!id || !data || len <= 0) {
        printf("ERROR: Invalid parameters for packet processing\n");
        return;
    }

    connection_entry_t* conn = find_connection(id);
    if (conn) {
        input_cb(conn, data, len);
        conn_unref(conn);  // Release reference
    }
}

int lwip_tcp_send(const char* id, const char* dest_ip_str, int port, const char* message) {
    if (!id || !dest_ip_str || port <= 0 || port > 65535) {
        printf("ERROR: Invalid parameters for connection\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;

    ip_addr_t dest_ip;
    if (!ipaddr_aton(dest_ip_str, &dest_ip)) {
        printf("ERROR: Invalid destination IP address\n");
        conn_unref(conn);
        return -1;
    }

    lwip_lock();

    if (conn->pcb != NULL) {
        printf("ERROR: Connection %s already active\n", id);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    conn->pcb = tcp_new();
    if (!conn->pcb) {
        lwip_unlock();
        printf("Failed to allocate new PCB for connection %s\n", id);
        conn_unref(conn);
        return -1;
    }

    conn->pcb->local_ip = conn->src_ip;
    
    // Disable Nagle's algorithm for reduced latency (optimization)
    tcp_nagle_disable(conn->pcb);

    if (message) {
        // Use local buffer to avoid strdup overhead when possible
        size_t msg_len = strlen(message);
        if (msg_len > 0) {
            conn->message = _strdup(message);
            if (!conn->message) {
                tcp_abort(conn->pcb);
                conn->pcb = NULL;
                lwip_unlock();
                printf("ERROR: Failed to duplicate message\n");
                conn_unref(conn);
                return -1;
            }
        }
    }

    err_t bind_result = tcp_bind(conn->pcb, &conn->pcb->local_ip, 0);
    if (bind_result != ERR_OK) {
        printf("ERROR: tcp_bind failed: %d\n", bind_result);
        tcp_abort(conn->pcb);
        if (conn->message) {
            free(conn->message);
            conn->message = NULL;
        }
        conn->pcb = NULL;
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    tcp_arg(conn->pcb, conn);
    tcp_recv(conn->pcb, tcp_recv_cb);
    tcp_err(conn->pcb, on_tcp_error);

    conn_ref(conn);  // Add reference for callbacks
    err_t ret = tcp_connect(conn->pcb, &dest_ip, port, tcp_connected);

    if (ret != ERR_OK) {
        printf("ERROR: tcp_connect failed: %d\n", ret);
        // Clean up on connect failure
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
        if (conn->message) {
            free(conn->message);
            conn->message = NULL;
        }
        lwip_unlock();
        conn_unref(conn);  // Remove callback reference
        conn_unref(conn);  // Remove find reference
        return -1;
    }

    lwip_unlock();
    conn_unref(conn);  // Release find reference
    return 0;
}

// Create persistent TCP connection (avoids handshake overhead)
int lwip_tcp_connect_persistent(const char* id, const char* dest_ip_str, int port, send_ack_complete_callback_t ack_cb) {
    if (!id || !dest_ip_str || port <= 0 || port > 65535) {
        printf("ERROR: Invalid parameters for persistent connection\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;

    ip_addr_t dest_ip;
    if (!ipaddr_aton(dest_ip_str, &dest_ip)) {
        printf("ERROR: Invalid destination IP address\n");
        conn_unref(conn);
        return -1;
    }

    lwip_lock();

    if (conn->pcb != NULL) {
        printf("ERROR: Connection %s already active\n", id);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    conn->pcb = tcp_new();
    if (!conn->pcb) {
        lwip_unlock();
        printf("Failed to allocate new PCB for connection %s\n", id);
        conn_unref(conn);
        return -1;
    }

    conn->pcb->local_ip = conn->src_ip;
    conn->persistent_mode = 1;  // Enable persistent mode
    
    // Set ACK callback for message tracking
    conn->send_ack_complete_callback = ack_cb;
    
    // Disable Nagle's algorithm for reduced latency
    tcp_nagle_disable(conn->pcb);

    err_t bind_result = tcp_bind(conn->pcb, &conn->pcb->local_ip, 0);
    if (bind_result != ERR_OK) {
        printf("ERROR: tcp_bind failed: %d\n", bind_result);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
        conn->send_ack_complete_callback = NULL;
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    tcp_arg(conn->pcb, conn);
    tcp_recv(conn->pcb, tcp_recv_cb);
    tcp_err(conn->pcb, on_tcp_error);

    conn_ref(conn);  // Add reference for callbacks
    err_t ret = tcp_connect(conn->pcb, &dest_ip, port, tcp_connected);

    if (ret != ERR_OK) {
        printf("ERROR: tcp_connect failed: %d\n", ret);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
        conn->persistent_mode = 0;
        conn->send_ack_complete_callback = NULL;
        lwip_unlock();
        conn_unref(conn);
        conn_unref(conn);
        return -1;
    }

    lwip_unlock();
    conn_unref(conn);
    return 0;
}

// Send data on persistent connection with message ID tracking
// Message ID is mandatory - use it to track ACK callbacks
int lwip_tcp_send_persistent(const char* id, const uint8_t* data, int len, const char* message_id) {
    if (!id || !data || len <= 0 || !message_id) {
        printf("ERROR: Invalid parameters for persistent send\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;

    lwip_lock();

    if (!conn->pcb || !conn->persistent_mode) {
        printf("ERROR: No persistent connection active for %s\n", id);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    // IMPORTANT: Check if there's enough buffer space BEFORE writing
    u16_t available = tcp_sndbuf(conn->pcb);
    if (available == 0) {
        printf("WARNING: TCP send buffer full (0 bytes available). Caller should retry after lwip_poll().\n");
        lwip_unlock();
        conn_unref(conn);
        return -2;
    }
    
    if ((int)available < len) {
        lwip_unlock();
        conn_unref(conn);
        return -2;  // Return buffer full - caller should retry
    }

    // Allocate ACK tracking entry
    pending_ack_entry_t* ack_entry = (pending_ack_entry_t*)malloc(sizeof(pending_ack_entry_t));
    if (!ack_entry) {
        printf("ERROR: Failed to allocate ACK tracking entry\n");
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }
    
    // Duplicate message ID string
    ack_entry->message_id = _strdup(message_id);
    if (!ack_entry->message_id) {
        printf("ERROR: Failed to duplicate message ID\n");
        free(ack_entry);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }
    
    ack_entry->bytes_sent = (u16_t)len;
    ack_entry->next = NULL;

    // Buffer has enough space - proceed with write
    err_t wr = tcp_write(conn->pcb, data, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (wr == ERR_OK) {
        // Add to pending ACK queue
        if (conn->pending_acks_tail) {
            conn->pending_acks_tail->next = ack_entry;
        } else {
            conn->pending_acks_head = ack_entry;
        }
        conn->pending_acks_tail = ack_entry;
        
        tcp_output(conn->pcb);
        lwip_unlock();
        
        // Call send_complete callback (not ACK callback - that comes later in on_tcp_sent_persistent)
        if (conn->send_complete_callback) {
            conn->send_complete_callback();
        }
        
        conn_unref(conn);
        return 0;
    }
    else {
        // Failed to send - free ACK entry and message ID
        free(ack_entry->message_id);
        free(ack_entry);
        
        if (wr == ERR_MEM) {
            lwip_unlock();
            conn_unref(conn);
            return -2;  // Retry
        }
        else {
            // Fatal error (not buffer related)
            printf("ERROR: tcp_write failed with error: %d\n", wr);
            lwip_unlock();
            conn_unref(conn);
            return -1;  // Fatal
        }
    }
}

// Close persistent connection
void lwip_tcp_disconnect_persistent(const char* id) {
    if (!id) return;

    connection_entry_t* conn = find_connection(id);
    if (!conn) return;

    lwip_lock();

    if (conn->pcb && conn->persistent_mode) {
        // CRITICAL: Clear callbacks FIRST to prevent use-after-free
        conn->send_complete_callback = NULL;
        conn->send_ack_complete_callback = NULL;
        
        // Clean up pending ACK queue (including message ID strings)
        while (conn->pending_acks_head) {
            pending_ack_entry_t* next = conn->pending_acks_head->next;
            if (conn->pending_acks_head->message_id) {
                free(conn->pending_acks_head->message_id);
            }
            free(conn->pending_acks_head);
            conn->pending_acks_head = next;
        }
        conn->pending_acks_tail = NULL;
        
        // Clear persistent_mode to prevent normal callbacks
        conn->persistent_mode = 0;
        
        // Clear non-error callbacks
        tcp_arg(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        
        // Keep tcp_err callback so on_tcp_error can handle conn_unref
        
        if (netif_is_up(&conn->netif)) {
            err_t close_err = tcp_close(conn->pcb);
            if (close_err != ERR_OK) {
                printf("tcp_close failed: %d, aborting\n", close_err);
                tcp_abort(conn->pcb);  // This will call on_tcp_error
            } else {
                // tcp_close succeeded - connection closed gracefully
                // We need to manually release callback reference since no error callback
                tcp_err(conn->pcb, NULL);  // Clear error callback now
                conn_unref(conn);  // Release callback reference
            }
        } else {
            tcp_abort(conn->pcb);  // This will call on_tcp_error with ERR_ABRT
        }
        
        conn->pcb = NULL;
        // Do NOT call conn_unref here if tcp_abort was called - on_tcp_error will handle it
        // conn_unref is called above only if tcp_close succeeded
    }

    lwip_unlock();
    conn_unref(conn);  // Release find_connection reference
}

// Control Nagle's algorithm
int lwip_tcp_set_nodelay(const char* id, int enable) {
    if (!id) return -1;

    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;

    lwip_lock();

    if (!conn->pcb) {
        printf("ERROR: No active TCP connection for %s\n", id);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    if (enable) {
        tcp_nagle_disable(conn->pcb);
    } else {
        tcp_nagle_enable(conn->pcb);
    }

    lwip_unlock();
    conn_unref(conn);
    return 0;
}

// Get available send buffer space for persistent connection
int lwip_tcp_get_send_buffer_available(const char* id) {
    if (!id) return -1;

    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;

    lwip_lock();

    if (!conn->pcb || !conn->persistent_mode) {
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    u16_t available = tcp_sndbuf(conn->pcb);
    
    lwip_unlock();
    conn_unref(conn);
    
    return (int)available;
}

int lwip_udp_send(const char* id, const char* dest_ip_str, int port, const uint8_t* data, int len) {
    if (!id || !dest_ip_str || port <= 0 || port > 65535 || !data || len <= 0) {
        printf("ERROR: Invalid parameters for UDP send\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) {
        printf("ERROR: Connection '%s' not found for UDP send\n", id);
        return -1;
    }

    ip_addr_t dest_ip;
    if (!ipaddr_aton(dest_ip_str, &dest_ip)) {
        printf("ERROR: Invalid destination IP address for UDP send\n");
        conn_unref(conn);
        return -1;
    }

    lwip_lock();

    // Reuse existing UDP PCB if available (optimization - like persistent connection)
    if (conn->udp_pcb == NULL) {
        // Create UDP PCB only once
        conn->udp_pcb = udp_new();
        if (!conn->udp_pcb) {
            printf("ERROR: Failed to create UDP PCB for connection '%s'\n", id);
            lwip_unlock();
            conn_unref(conn);
            return -1;
        }

        // Bind to local port
        err_t err = udp_bind(conn->udp_pcb, &conn->src_ip, 0);
        if (err != ERR_OK) {
            printf("ERROR: UDP bind failed for connection '%s': %d\n", id, err);
            udp_remove(conn->udp_pcb);
            conn->udp_pcb = NULL;
            lwip_unlock();
            conn_unref(conn);
            return -1;
        }

        // Set receive callback
        udp_recv(conn->udp_pcb, udp_recv_cb, conn);
    }

    // Allocate pbuf for the data
    struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) {
        printf("ERROR: Failed to allocate pbuf for UDP send\n");
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    // Copy data to pbuf
    if (pbuf_take(p, data, len) != ERR_OK) {
        printf("ERROR: Failed to copy data to pbuf for UDP send\n");
        pbuf_free(p);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    // Send the packet (reusing existing PCB)
    err_t err_sendto = udp_sendto(conn->udp_pcb, p, &dest_ip, port);

    // Cleanup pbuf
    pbuf_free(p);

    if (err_sendto != ERR_OK) {
        printf("ERROR: UDP send failed: %d\n", err_sendto);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    lwip_unlock();

    if (conn->send_complete_callback) {
        conn->send_complete_callback();
    }

    conn_unref(conn);
    
    return 0;
}


void lwip_close_connection(const char* id) {
    if (!id) {
        printf("ERROR: Invalid connection ID\n");
        return;
    }

    lwip_lock();
    connection_entry_t** prev = &connection_list;
    connection_entry_t* conn = connection_list;

    while (conn) {
        if (conn->id && strcmp(conn->id, id) == 0) {
            // Remove from list first
            *prev = conn->next;
            
            // CRITICAL: Clear all callbacks to prevent use-after-free
            // This prevents C# code from calling back into freed memory
            conn->send_complete_callback = NULL;
            conn->send_ack_complete_callback = NULL;
            conn->udp_callback = NULL;
            
            // Clean up pending ACK queue (including message ID strings)
            while (conn->pending_acks_head) {
                pending_ack_entry_t* next = conn->pending_acks_head->next;
                if (conn->pending_acks_head->message_id) {
                    free(conn->pending_acks_head->message_id);
                }
                free(conn->pending_acks_head);
                conn->pending_acks_head = next;
            }
            conn->pending_acks_tail = NULL;

            // Close TCP connection if active - do this BEFORE removing netif
            if (conn->pcb) {
                // IMPORTANT: Clear persistent_mode FIRST to prevent normal callbacks
                conn->persistent_mode = 0;
                
                // Clear non-error callbacks
                tcp_arg(conn->pcb, NULL);
                tcp_sent(conn->pcb, NULL);
                tcp_recv(conn->pcb, NULL);
                
                // Keep tcp_err callback - tcp_abort() will call it with ERR_ABRT
                // on_tcp_error will then call conn_unref() to release callback reference
                // This ensures proper cleanup without use-after-free
                
                tcp_abort(conn->pcb);  // This calls on_tcp_error with ERR_ABRT
                conn->pcb = NULL;
                
                // Do NOT call conn_unref here - on_tcp_error will handle it
            }

            // Close UDP connection if active
            if (conn->udp_pcb) {
                udp_remove(conn->udp_pcb);
                conn->udp_pcb = NULL;
            }

            // Now cleanup network interface
            netif_set_down(&conn->netif);
            netif_remove(&conn->netif);

            lwip_unlock();

            // Release initial reference - this may trigger cleanup
            conn_unref(conn);

            printf("Connection '%s' closed and removed.\n", id);
            return;
        }
        prev = &conn->next;
        conn = conn->next;
    }

    lwip_unlock();
    printf("Connection '%s' not found to close.\n", id);
}

void* ip4_route_custom(const void* src, const void* dest) {
    if (!src) {
        return NULL;
    }

    const ip4_addr_t* src_ip4 = (const ip4_addr_t*)src;

    lwip_lock();
    connection_entry_t* conn = connection_list;
    while (conn) {
        if (ip4_addr_cmp(&conn->src_ip, src_ip4)) {
            struct netif* result = &conn->netif;
            lwip_unlock();            
            return result;
        }
        conn = conn->next;
    }
    lwip_unlock();

    return NULL;
}


void lwip_cleanup_all_connections() {
    lwip_lock();

    while (connection_list) {
        connection_entry_t* conn = connection_list;
        connection_list = conn->next;

        netif_set_down(&conn->netif);
        netif_remove(&conn->netif);

        if (conn->pcb) {
            tcp_abort(conn->pcb);
        }

        if (conn->udp_pcb) {
            udp_remove(conn->udp_pcb);
        }

        conn_unref(conn);
    }

    lwip_unlock();
    cleanup_lwip_lock();
}

int lwip_tcp_get_pending_ack_count(const char* id) {
    if (!id) return -1;
    
    connection_entry_t* conn = find_connection(id);
    if (!conn) return -1;
    
    lwip_lock();
    int count = 0;
    pending_ack_entry_t* entry = conn->pending_acks_head;
    while (entry) {
        count++;
        entry = entry->next;
    }
    lwip_unlock();
    
    conn_unref(conn);
    return count;
}

// ===== BATCH OPTIMIZATION FUNCTIONS =====

// Batch TCP send with TCP_WRITE_FLAG_MORE for maximum throughput
// Combines multiple messages into fewer TCP packets
int lwip_tcp_send_batch_optimized(const char* id,
                                   const char* dest_ip_str,
                                   int port,
                                   const uint8_t** data_array,
                                   const int* len_array,
                                   const char** message_ids,
                                   int batch_size) {
    if (!id || !dest_ip_str || port <= 0 || port > 65535 || 
        !data_array || !len_array || !message_ids || batch_size <= 0) {
        printf("ERROR: Invalid parameters for TCP batch send\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) {
        printf("ERROR: Connection '%s' not found\n", id);
        return -1;
    }

    lwip_lock();

    if (!conn->pcb || !conn->persistent_mode) {
        printf("ERROR: No persistent TCP connection active for %s\n", id);
        lwip_unlock();
        conn_unref(conn);
        return -1;
    }

    int successful_sends = 0;
    int total_bytes = 0;

    // Calculate total bytes needed
    for (int i = 0; i < batch_size; i++) {
        total_bytes += len_array[i];
    }

    // Check if buffer has enough space for entire batch
    u16_t available = tcp_sndbuf(conn->pcb);
    if ((int)available < total_bytes) {
        printf("WARNING: TCP buffer (%d) < required (%d). Send what fits.\n", available, total_bytes);
        lwip_unlock();
        conn_unref(conn);
        return -2;  // Buffer full
    }

    // Write all messages with TCP_WRITE_FLAG_MORE except the last
    for (int i = 0; i < batch_size; i++) {
        // Create ACK tracking entry
        pending_ack_entry_t* ack_entry = (pending_ack_entry_t*)malloc(sizeof(pending_ack_entry_t));
        if (!ack_entry) {
            printf("ERROR: Failed to allocate ACK tracking entry\n");
            break;
        }

        ack_entry->message_id = _strdup(message_ids[i]);
        if (!ack_entry->message_id) {
            free(ack_entry);
            continue;  // Skip this message
        }

        ack_entry->bytes_sent = (u16_t)len_array[i];
        ack_entry->next = NULL;

        // ? KEY: Use TCP_WRITE_FLAG_MORE for all except last message
        u8_t flags = TCP_WRITE_FLAG_COPY;
        if (i < batch_size - 1) {
            flags |= TCP_WRITE_FLAG_MORE;  // Tell TCP: more data coming, buffer it
        }

        err_t wr = tcp_write(conn->pcb, data_array[i], (u16_t)len_array[i], flags);
        
        if (wr == ERR_OK) {
            // Add to pending ACK queue
            if (conn->pending_acks_tail) {
                conn->pending_acks_tail->next = ack_entry;
            } else {
                conn->pending_acks_head = ack_entry;
            }
            conn->pending_acks_tail = ack_entry;
            
            successful_sends++;
        } else {
            // Failed to write this message
            printf("ERROR: tcp_write failed for message %d: %d\n", i, wr);
            free(ack_entry->message_id);
            free(ack_entry);
            break;  // Stop on first failure
        }
    }

    // ? Flush ALL buffered data with single tcp_output() call
    if (successful_sends > 0) {
        tcp_output(conn->pcb);
        
        // Call send_complete callback once for entire batch
        if (conn->send_complete_callback) {
            conn->send_complete_callback();
        }
    }

    lwip_unlock();
    conn_unref(conn);
    
    return successful_sends;
}

// Batch UDP send optimization
// Sends multiple UDP datagrams with minimal overhead
int lwip_udp_send_batch_optimized(const char* id,
                                   const char* dest_ip_str,
                                   int port,
                                   const uint8_t** data_array,
                                   const int* len_array,
                                   int batch_size) {
    if (!id || !dest_ip_str || port <= 0 || port > 65535 || 
        !data_array || !len_array || batch_size <= 0) {
        printf("ERROR: Invalid parameters for UDP batch send\n");
        return -1;
    }

    connection_entry_t* conn = find_connection(id);
    if (!conn) {
        printf("ERROR: Connection '%s' not found\n", id);
        return -1;
    }

    ip_addr_t dest_ip;
    if (!ipaddr_aton(dest_ip_str, &dest_ip)) {
        printf("ERROR: Invalid destination IP address\n");
        conn_unref(conn);
        return -1;
    }

    lwip_lock();

    // Create/reuse UDP PCB
    if (conn->udp_pcb == NULL) {
        conn->udp_pcb = udp_new();
        if (!conn->udp_pcb) {
            printf("ERROR: Failed to create UDP PCB\n");
            lwip_unlock();
            conn_unref(conn);
            return -1;
        }

        err_t err = udp_bind(conn->udp_pcb, &conn->src_ip, 0);
        if (err != ERR_OK) {
            printf("ERROR: UDP bind failed: %d\n", err);
            udp_remove(conn->udp_pcb);
            conn->udp_pcb = NULL;
            lwip_unlock();
            conn_unref(conn);
            return -1;
        }

        udp_recv(conn->udp_pcb, udp_recv_cb, conn);
    }

    int successful_sends = 0;

    // Send all datagrams in batch
    // UDP is connectionless, so we optimize by:
    // 1. Reusing the same UDP PCB
    // 2. Minimizing allocations
    // 3. Sending to same destination
    for (int i = 0; i < batch_size; i++) {
        // Allocate pbuf for this datagram
        struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, len_array[i], PBUF_RAM);
        if (!p) {
            printf("ERROR: Failed to allocate pbuf for message %d\n", i);
            break;  // Stop on first allocation failure
        }

        // Copy data to pbuf
        if (pbuf_take(p, data_array[i], len_array[i]) != ERR_OK) {
            printf("ERROR: Failed to copy data for message %d\n", i);
            pbuf_free(p);
            break;
        }

        // Send the datagram
        err_t err = udp_sendto(conn->udp_pcb, p, &dest_ip, port);
        pbuf_free(p);

        if (err == ERR_OK) {
            successful_sends++;
        } else {
            printf("ERROR: UDP send failed for message %d: %d\n", i, err);
            // Continue with next message (UDP is best-effort anyway)
        }
    }

    lwip_unlock();

    // Call send_complete callback once for entire batch
    if (successful_sends > 0 && conn->send_complete_callback) {
        conn->send_complete_callback();
    }

    conn_unref(conn);
    
    return successful_sends;
}
