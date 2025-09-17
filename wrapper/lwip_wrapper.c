#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/etharp.h"

#include "lwip_wrapper.h"

typedef struct connection_entry {
    char* id;
    struct netif netif;
    struct tcp_pcb* pcb;
    ip4_addr_t src_ip;
    char* message;
    udp_send_callback_t udp_callback;
    tcp_send_complete_callback_t tcp_complete_callback;
    struct connection_entry* next;
    volatile int ref_count;  // Reference counting for safe cleanup
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
        free(conn);
    }
}

static err_t output_cb(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
    if (!netif || !netif->state || !p) {
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

static err_t on_tcp_sent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
    connection_entry_t* conn = (connection_entry_t*)arg;
    if (!conn) return ERR_ARG;

    printf("TCP sent callback (len = %u)\n", len);

    if (conn->tcp_complete_callback) {
        conn->tcp_complete_callback();
    }

    lwip_lock();
    if (tpcb && conn->pcb == tpcb) {
        tcp_arg(tpcb, NULL);
        tcp_sent(tpcb, NULL);
        tcp_recv(tpcb, NULL);
        tcp_err(tpcb, NULL);
        tcp_close(tpcb);
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
    if (conn->message && strlen(conn->message) > 0) {
        err_t wr = tcp_write(tpcb, conn->message, strlen(conn->message), TCP_WRITE_FLAG_COPY);
        if (wr == ERR_OK) {
            tcp_output(tpcb);
            tcp_sent(tpcb, on_tcp_sent);
            tcp_arg(tpcb, conn);  // Keep reference for sent callback
            conn_ref(conn);  // Add reference for sent callback
        }
        else {
            printf("tcp_write failed: %d\n", wr);
            conn_unref(conn);
        }
        free(conn->message);
        conn->message = NULL;
    }
    else {
        conn_unref(conn);  // No message to send, release reference
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

    printf("Received: %.*s\n", (int)p->len, (char*)p->payload);

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
        lwip_unlock();
        conn_unref(conn);
    }
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
    tcp_send_complete_callback_t tcp_complete_cb) {

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

    // Check if connection already exists
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
    conn->tcp_complete_callback = tcp_complete_cb;
    conn->netif.state = conn;
    conn->ref_count = 1;  // Initial reference

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
    printf("Connection '%s' created successfully\n", id);
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

void lwip_process_packet(const char* id, uint8_t* data, int len) {
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

int lwip_connect(const char* id, const char* dest_ip_str, int port, const char* message) {
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
        printf("Connection %s already active\n", id);
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

    if (message) {
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

    err_t bind_result = tcp_bind(conn->pcb, &conn->pcb->local_ip, 0);
    if (bind_result != ERR_OK) {
        printf("tcp_bind failed: %d\n", bind_result);
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

    lwip_unlock();

    if (ret != ERR_OK) {
        printf("tcp_connect failed: %d\n", ret);
        conn_unref(conn);  // Remove callback reference
        conn_unref(conn);  // Remove find reference
        return -1;
    }

    printf("tcp_connect to %s:%d with ID '%s' initiated successfully\n", dest_ip_str, port, id);
    conn_unref(conn);  // Release find reference
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

            // Cleanup network interface
            netif_set_down(&conn->netif);
            netif_remove(&conn->netif);

            // Close TCP connection if active
            if (conn->pcb) {
                tcp_abort(conn->pcb);
                conn->pcb = NULL;
            }

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

/*
struct netif* ip4_route_custom(const ip4_addr_t* src, const ip4_addr_t* dest) {
    if (!src) {
        printf("ip4_route_custom: source IP is NULL\n");
        return NULL;
    }

    lwip_lock();
    connection_entry_t* conn = connection_list;
    while (conn) {
        if (ip4_addr_cmp(&conn->src_ip, src)) {
            struct netif* result = &conn->netif;
            lwip_unlock();
            return result;
        }
        conn = conn->next;
    }
    lwip_unlock();

    printf("Netif not found for source IP %s\n", ip4addr_ntoa(src));
    return NULL;
}
*/

void* ip4_route_custom(const void* src, const void* dest) {
    if (!src) {
        printf("ip4_route_custom: source IP is empty\n");
        return NULL;
    }

    ip4_addr_t* src_ip = (ip4_addr_t*)src;

    lwip_lock();
    connection_entry_t* conn = connection_list;
    while (conn) {
        if (ip4_addr_cmp(&conn->src_ip, src_ip)) {
            struct netif* result = &conn->netif;
            lwip_unlock();
            return result;
        }
        conn = conn->next;
    }
    lwip_unlock();

    printf("Netif is not found\n");

    return NULL;
}


// Cleanup function for graceful shutdown
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

        conn_unref(conn);
    }

    lwip_unlock();
    cleanup_lwip_lock();
}