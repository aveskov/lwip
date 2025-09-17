#ifndef SSL_MINIMAL_H
#define SSL_MINIMAL_H

#ifdef __cplusplus
extern "C" {
#endif

	// Forward declarations to avoid including full BoringSSL headers
	typedef struct ssl_ctx_st SSL_CTX;
	typedef struct ssl_st SSL;
	typedef struct bio_st BIO;
	typedef struct x509_store_ctx_st X509_STORE_CTX;

	// Essential SSL constants
#define SSL_ERROR_NONE 0
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL 5
#define SSL_ERROR_ZERO_RETURN 6
#define SSL_ERROR_WANT_CONNECT 7
#define SSL_ERROR_WANT_ACCEPT 8

#define SSL_VERIFY_NONE 0
#define SSL_VERIFY_PEER 1

#define SSL_FILETYPE_PEM 1

// Function declarations (manually declared to avoid header issues)
	SSL_CTX* SSL_CTX_new(const void* method);
	void SSL_CTX_free(SSL_CTX* ctx);
	long SSL_CTX_set_options(SSL_CTX* ctx, long options);
	void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, void* callback);
	int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx);
	int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* CAfile, const char* CApath);
	int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int type);
	int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int type);

	SSL* SSL_new(SSL_CTX* ctx);
	void SSL_free(SSL* ssl);
	int SSL_set_fd(SSL* ssl, int fd);
	void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio);
	void SSL_set_connect_state(SSL* ssl);
	int SSL_connect(SSL* ssl);
	int SSL_do_handshake(SSL* ssl);
	int SSL_read(SSL* ssl, void* buf, int num);
	int SSL_write(SSL* ssl, const void* buf, int num);
	int SSL_shutdown(SSL* ssl);
	int SSL_get_error(const SSL* ssl, int ret);
	int SSL_set_tlsext_host_name(SSL* ssl, const char* name);

	BIO* BIO_new(const void* type);
	void BIO_free(BIO* bio);
	int BIO_read(BIO* bio, void* data, int len);
	int BIO_write(BIO* bio, const void* data, int len);
	int BIO_pending(BIO* bio);
	const void* BIO_s_mem(void);

	const void* TLS_client_method(void);

	void SSL_library_init(void);
	void SSL_load_error_strings(void);
	void OpenSSL_add_all_algorithms(void);
	unsigned long ERR_get_error(void);
	void ERR_error_string_n(unsigned long e, char* buf, size_t len);
	void EVP_cleanup(void);
	void ERR_free_strings(void);

	// SSL options
#define SSL_OP_NO_SSLv2   0x01000000UL
#define SSL_OP_NO_SSLv3   0x02000000UL
#define SSL_OP_NO_TLSv1   0x04000000UL
#define SSL_OP_NO_TLSv1_1 0x10000000UL

#ifdef __cplusplus
}
#endif

#endif // SSL_MINIMAL_H