extern "C" {
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

#include "lwip_wrapper.h"
}

// Use minimal SSL header instead of full BoringSSL headers
#include "ssl_minimal.h"
#include "lwip_wrapper_ssl.h"

// Wrap everything in extern "C" for C linkage
extern "C" {

    // SSL connection states
    typedef enum {
        SSL_STATE_CONNECTING,
        SSL_STATE_HANDSHAKING,
        SSL_STATE_CONNECTED,
        SSL_STATE_CLOSING,
        SSL_STATE_CLOSED,
        SSL_STATE_ERROR
    } ssl_connection_state_t;

    typedef struct ssl_connection_entry {
        char* id;
        struct tcp_pcb* pcb;
        struct netif* base_netif;

        // SSL context
        SSL_CTX* ssl_ctx;
        SSL* ssl;
        BIO* rbio;
        BIO* wbio;

        char* hostname;
        ssl_connection_state_t state;

        // Callbacks
        ssl_handshake_complete_callback_t handshake_complete_callback;
        ssl_data_received_callback_t data_received_callback;
        ssl_send_complete_callback_t ssl_complete_callback;

        struct ssl_connection_entry* next;
        volatile LONG ref_count;
    } ssl_connection_entry_t;

    static ssl_connection_entry_t* ssl_connection_list = NULL;
    static CRITICAL_SECTION ssl_lock_var;
    static volatile int ssl_initialized = 0;
    static SSL_CTX* global_ssl_ctx = NULL;

#define ssl_lock()   EnterCriticalSection(&ssl_lock_var)
#define ssl_unlock() LeaveCriticalSection(&ssl_lock_var)

    // Helper functions for reference counting
    static void ssl_conn_ref(ssl_connection_entry_t* conn) {
        if (conn) {
            InterlockedIncrement(&conn->ref_count);
        }
    }

    static void ssl_conn_unref(ssl_connection_entry_t* conn) {
        if (conn && InterlockedDecrement(&conn->ref_count) == 0) {
            if (conn->ssl) {
                SSL_free(conn->ssl);
            }
            if (conn->ssl_ctx) {
                SSL_CTX_free(conn->ssl_ctx);
            }
            if (conn->id) free(conn->id);
            if (conn->hostname) free(conn->hostname);
            free(conn);
        }
    }

    static ssl_connection_entry_t* find_ssl_connection_locked(const char* id) {
        if (!id) return NULL;

        ssl_connection_entry_t* conn = ssl_connection_list;
        while (conn) {
            if (conn->id && strcmp(conn->id, id) == 0) {
                return conn;
            }
            conn = conn->next;
        }
        return NULL;
    }

    static ssl_connection_entry_t* find_ssl_connection(const char* id) {
        ssl_lock();
        ssl_connection_entry_t* conn = find_ssl_connection_locked(id);
        if (conn) {
            ssl_conn_ref(conn);
        }
        ssl_unlock();

        if (!conn) {
            printf("ERROR: SSL Connection '%s' not found.\n", id ? id : "NULL");
        }
        return conn;
    }

    static void ssl_handle_error(ssl_connection_entry_t* conn, const char* operation) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("SSL Error in %s: %s\n", operation, err_buf);

        conn->state = SSL_STATE_ERROR;

        if (conn->handshake_complete_callback && conn->state == SSL_STATE_HANDSHAKING) {
            conn->handshake_complete_callback(0);  // Failed
        }
    }

    static void ssl_flush_write_bio(ssl_connection_entry_t* conn) {
        if (!conn->wbio || !conn->pcb) return;

        char buf[4096];
        int pending = BIO_pending(conn->wbio);

        while (pending > 0) {
            int to_read = (pending > sizeof(buf)) ? sizeof(buf) : pending;
            int read_bytes = BIO_read(conn->wbio, buf, to_read);

            if (read_bytes <= 0) break;

            // Send via TCP
            lwip_lock();
            err_t err = tcp_write(conn->pcb, buf, read_bytes, TCP_WRITE_FLAG_COPY);
            if (err == ERR_OK) {
                tcp_output(conn->pcb);
            }
            else {
                printf("ERROR: Failed to send SSL data via TCP: %d\n", err);
            }
            lwip_unlock();

            if (err != ERR_OK) break;

            pending = BIO_pending(conn->wbio);
        }
    }

    static void ssl_process_handshake(ssl_connection_entry_t* conn) {
        if (conn->state != SSL_STATE_HANDSHAKING) return;        

        int ret = SSL_do_handshake(conn->ssl);
        ssl_flush_write_bio(conn);

        if (ret == 1) {
            // Handshake completed successfully
            conn->state = SSL_STATE_CONNECTED;            

            if (conn->handshake_complete_callback) {
                conn->handshake_complete_callback(1);  // Success
            }
        }
        else {
            int ssl_error = SSL_get_error(conn->ssl, ret);            

            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Need more data, continue handshake later
                return;
            }
            else {
                // Handshake failed
                ssl_handle_error(conn, "handshake");
            }
        }
    }

    static void ssl_process_application_data(ssl_connection_entry_t* conn) {
        if (conn->state != SSL_STATE_CONNECTED) return;

        char buf[4096];
        int bytes_read;

        do {
            bytes_read = SSL_read(conn->ssl, buf, sizeof(buf));
            ssl_flush_write_bio(conn);

            if (bytes_read > 0) {
                // Successfully read application data
                if (conn->data_received_callback) {
                    conn->data_received_callback((const uint8_t*)buf, bytes_read);
                }
            }
            else {
                int ssl_error = SSL_get_error(conn->ssl, bytes_read);

                if (ssl_error == SSL_ERROR_WANT_READ) {
                    // No more data available right now
                    break;
                }
                else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    // SSL connection closed cleanly
                    printf("SSL connection closed cleanly for '%s'\n", conn->id);
                    conn->state = SSL_STATE_CLOSED;
                    break;
                }
                else {
                    // SSL error
                    ssl_handle_error(conn, "read");
                    break;
                }
            }
        } while (bytes_read > 0);
    }

    // TCP callbacks for SSL connections
    static err_t ssl_tcp_recv_cb(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
        ssl_connection_entry_t* conn = (ssl_connection_entry_t*)arg;

        if (!conn) return ERR_ARG;

        if (!p) {
            printf("Remote closed SSL connection '%s'\n", conn->id);
            conn->state = SSL_STATE_CLOSED;
            ssl_conn_unref(conn);
            return ERR_OK;
        }

        if (err != ERR_OK) {
            pbuf_free(p);
            ssl_conn_unref(conn);
            return err;
        }

        // Feed data into read BIO
        struct pbuf* q = p;
        while (q) {
            BIO_write(conn->rbio, q->payload, q->len);
            q = q->next;
        }

        lwip_lock();
        tcp_recved(tpcb, p->tot_len);
        lwip_unlock();
        pbuf_free(p);

        // Process SSL data based on current state
        switch (conn->state) {
        case SSL_STATE_HANDSHAKING:
            ssl_process_handshake(conn);
            break;

        case SSL_STATE_CONNECTED:
            ssl_process_application_data(conn);
            break;

        default:
            break;
        }

        return ERR_OK;
    }

    static void ssl_tcp_err_cb(void* arg, err_t err) {
        ssl_connection_entry_t* conn = (ssl_connection_entry_t*)arg;
        printf("SSL TCP error for connection '%s': %d\n", conn ? conn->id : "unknown", err);

        if (conn) {
            conn->state = SSL_STATE_ERROR;
            conn->pcb = NULL;
            ssl_conn_unref(conn);
        }
    }

    static err_t ssl_tcp_connected_cb(void* arg, struct tcp_pcb* tpcb, err_t err) {
        ssl_connection_entry_t* conn = (ssl_connection_entry_t*)arg;		

        if (!conn || err != ERR_OK) {
            if (conn) ssl_conn_unref(conn);
            return err;
        }        

        // Start SSL handshake
        conn->state = SSL_STATE_HANDSHAKING;
        ssl_process_handshake(conn);

        return ERR_OK;
    }

    static SSL_CTX* create_ssl_ctx() {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            return NULL;
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        
        return ctx;
    }

    void lwip_ssl_init_global(void) {
        if (!ssl_initialized) {
            InitializeCriticalSection(&ssl_lock_var);

            // Initialize BoringSSL
            SSL_library_init();
            SSL_load_error_strings();
            
            ssl_initialized = 1;            
        }
    }

    void lwip_ssl_cleanup_global(void) {
        if (ssl_initialized) {
            ssl_lock();

            // Cleanup all connections
            while (ssl_connection_list) {
                ssl_connection_entry_t* conn = ssl_connection_list;
                ssl_connection_list = conn->next;
                ssl_conn_unref(conn);
            }

            ssl_unlock();
            DeleteCriticalSection(&ssl_lock_var);

            // Cleanup BoringSSL
            EVP_cleanup();
            ERR_free_strings();

            ssl_initialized = 0;
        }
    }

    int lwip_ssl_connect(const char* id,
        const char* dest_ip_str,
        int port,
        const char* hostname,
        ssl_handshake_complete_callback_t handshake_complete_cb,
        ssl_data_received_callback_t data_received_cb,
        ssl_send_complete_callback_t ssl_complete_cb) {

        if (!id || !dest_ip_str || port <= 0 || port > 65535) {
            printf("ERROR: Invalid parameters for SSL connection\n");
            return -1;
        }

        if (!ssl_initialized) {
            printf("ERROR: SSL not initialized\n");
            return -1;
        }

        // Find the base connection
        connection_entry_t* base_conn = find_connection(id);
        if (!base_conn) {
            printf("ERROR: Base connection '%s' not found\n", id);
            return -1;
        }

        ssl_lock();

        // Check if SSL connection already exists
        if (find_ssl_connection_locked(id)) {
            ssl_unlock();
            conn_unref(base_conn);
            printf("ERROR: SSL connection '%s' already exists\n", id);
            return -1;
        }

        // Create SSL connection entry
        ssl_connection_entry_t* ssl_conn = (ssl_connection_entry_t*)calloc(1, sizeof(ssl_connection_entry_t));
        if (!ssl_conn) {
            ssl_unlock();
            conn_unref(base_conn);
            return -1;
        }

        ssl_conn->id = _strdup(id);
        ssl_conn->ref_count = 1;
        ssl_conn->state = SSL_STATE_CONNECTING;

        ssl_conn->base_netif = get_connection_netif(base_conn);

        if (hostname) {
            ssl_conn->hostname = _strdup(hostname);
        }

        // Set callbacks
        ssl_conn->handshake_complete_callback = handshake_complete_cb;
        ssl_conn->data_received_callback = data_received_cb;
        ssl_conn->ssl_complete_callback = ssl_complete_cb;
       
        // Create SSL objects
        ssl_conn->ssl_ctx = create_ssl_ctx();
        if (!ssl_conn->ssl_ctx) {
            printf("ERROR: Failed to create per-connection SSL_CTX with CA\n");
            free(ssl_conn->id);
            if (ssl_conn->hostname) free(ssl_conn->hostname);
            free(ssl_conn);
            ssl_unlock();
            conn_unref(base_conn);
            return -1;
        }

        ssl_conn->ssl = SSL_new(ssl_conn->ssl_ctx);
        ssl_conn->rbio = BIO_new(BIO_s_mem());
        ssl_conn->wbio = BIO_new(BIO_s_mem());

        if (!ssl_conn->ssl || !ssl_conn->rbio || !ssl_conn->wbio) {
            // Cleanup on failure
            if (ssl_conn->ssl) SSL_free(ssl_conn->ssl);
            if (ssl_conn->rbio) BIO_free(ssl_conn->rbio);
            if (ssl_conn->wbio) BIO_free(ssl_conn->wbio);
            free(ssl_conn->id);
            if (ssl_conn->hostname) free(ssl_conn->hostname);
            free(ssl_conn);
            ssl_unlock();
            conn_unref(base_conn);
            return -1;
        }

        SSL_set_bio(ssl_conn->ssl, ssl_conn->rbio, ssl_conn->wbio);
        SSL_set_connect_state(ssl_conn->ssl);

        if (hostname) {
            SSL_set_tlsext_host_name(ssl_conn->ssl, hostname);
        }

        // Add to SSL connection list
        ssl_conn->next = ssl_connection_list;
        ssl_connection_list = ssl_conn;

        ssl_unlock();
        conn_unref(base_conn);

        // Create TCP connection
        ip_addr_t dest_ip;
        if (!ipaddr_aton(dest_ip_str, &dest_ip)) {
            lwip_ssl_close_connection(id);
            return -1;
        }

        lwip_lock();
        ssl_conn->pcb = tcp_new();
        if (!ssl_conn->pcb) {
            lwip_unlock();
            lwip_ssl_close_connection(id);
            return -1;
        }		
        
        const ip_addr_t* src_ip_ptr = get_connection_src_ip(base_conn);
        if (!src_ip_ptr) {
            lwip_unlock();
            lwip_ssl_close_connection(id);
            conn_unref(base_conn);
            return -1;
        }

        ssl_conn->pcb->local_ip = *src_ip_ptr;

        err_t bind_result = tcp_bind(ssl_conn->pcb, src_ip_ptr, 0);
        if (bind_result != ERR_OK) {
            tcp_abort(ssl_conn->pcb);
            ssl_conn->pcb = NULL;
            lwip_unlock();
            lwip_ssl_close_connection(id);
            return -1;
        }

        tcp_bind_netif(ssl_conn->pcb, ssl_conn->base_netif);

        tcp_arg(ssl_conn->pcb, ssl_conn);
        tcp_recv(ssl_conn->pcb, ssl_tcp_recv_cb);
        tcp_err(ssl_conn->pcb, ssl_tcp_err_cb);

        ssl_conn_ref(ssl_conn);
        err_t connect_result = tcp_connect(ssl_conn->pcb, &dest_ip, port, ssl_tcp_connected_cb);

        lwip_unlock();

        if (connect_result != ERR_OK) {
            ssl_conn_unref(ssl_conn);
            lwip_ssl_close_connection(id);
            return -1;
        }

        return 0;
    }

    int lwip_ssl_send_data(const char* id, const uint8_t* data, int len) {
        ssl_connection_entry_t* conn = find_ssl_connection(id);
        if (!conn) return -1;

        if (conn->state != SSL_STATE_CONNECTED) {
            ssl_conn_unref(conn);
            return -1;
        }

        int bytes_written = SSL_write(conn->ssl, data, len);
        ssl_flush_write_bio(conn);

        int result = 0;
        if (bytes_written > 0) {
            if (conn->ssl_complete_callback) {
                conn->ssl_complete_callback();
            }
        }
        else {
            int ssl_error = SSL_get_error(conn->ssl, bytes_written);
            if (ssl_error != SSL_ERROR_WANT_WRITE && ssl_error != SSL_ERROR_WANT_READ) {
                ssl_handle_error(conn, "write");
                result = -1;
            }
        }

        ssl_conn_unref(conn);
        return result;
    }

    void lwip_ssl_close_connection(const char* id) {
        ssl_lock();
        ssl_connection_entry_t** prev = &ssl_connection_list;
        ssl_connection_entry_t* conn = ssl_connection_list;

        while (conn) {
            if (conn->id && strcmp(conn->id, id) == 0) {
                *prev = conn->next;

                if (conn->ssl && conn->state == SSL_STATE_CONNECTED) {
                    // Graceful TLS shutdown: call SSL_shutdown until it returns 1
                    int shutdown_status = SSL_shutdown(conn->ssl);
                    ssl_flush_write_bio(conn);
                    if (shutdown_status == 0) {
                        // Need to call a second time to wait for peer close_notify
                        shutdown_status = SSL_shutdown(conn->ssl);
                        ssl_flush_write_bio(conn);
                    }
                }

                conn->state = SSL_STATE_CLOSING;

                if (conn->pcb) {
                    lwip_lock();
                    // Attempt a graceful TCP close
                    err_t err = tcp_close(conn->pcb);
                    if (err != ERR_OK) {
                        // If tcp_close() fails (e.g. data unacked), you may want to wait/retry.
                        // As a last resort, fall back to abort:
                        tcp_abort(conn->pcb);
                    }
                    lwip_unlock();
                    conn->pcb = NULL;
                }

                ssl_unlock();
                ssl_conn_unref(conn);
                printf("SSL connection '%s' closed\n", id);
                return;
            }
            prev = &conn->next;
            conn = conn->next;
        }

        ssl_unlock();
    }
} // extern "C"