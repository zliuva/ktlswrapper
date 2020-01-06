#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/tls.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_internal.h>

static const char *cert, *key;
static in_port_t port;
static int target_sockfd = -1;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context srvkey;

static const int AES_128_CIPHERS[] = {
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    0x0
};

static int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*real_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*real_accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

#define PRINT_MBEDTLS_ERROR(errno) \
{ \
    char buf[256]; \
    mbedtls_strerror((errno), buf, sizeof(buf)); \
    fprintf(stderr, "[%s:%d] mbedtls error: %s\n", __FILE__, __LINE__, buf); \
}

#define ENSURE(x) \
{ \
    int ret = (x); \
    if (ret != 0) { \
        PRINT_MBEDTLS_ERROR(ret); \
        assert(false); \
    } \
}

static void init_ssl_conf(void) {
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&srvkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ENSURE(mbedtls_x509_crt_parse_file(&srvcert, cert));
    ENSURE(mbedtls_pk_parse_keyfile(&srvkey, key, NULL));

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    ENSURE(mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey));

    ENSURE(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0));
    ENSURE(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
}

bool set_crypto_info(int client, mbedtls_ssl_context *ssl, bool read) {
    struct tls12_crypto_info_aes_gcm_128 crypto_info = {
        .info = {
            .version = TLS_1_2_VERSION,
            .cipher_type = TLS_CIPHER_AES_GCM_128
        }
    };

    unsigned char *salt = read ? ssl->transform->iv_dec : ssl->transform->iv_enc;
    unsigned char *iv = salt + 4;
    unsigned char *rec_seq = read ? ssl->in_ctr : ssl->cur_out_ctr;
    
    mbedtls_gcm_context *gcm_context = read ? ssl->transform->cipher_ctx_dec.cipher_ctx : ssl->transform->cipher_ctx_enc.cipher_ctx;
    mbedtls_aes_context *aes_context = gcm_context->cipher_ctx.cipher_ctx;

    memcpy(crypto_info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info.key, aes_context->rk, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info.salt, salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    if (setsockopt(client, SOL_TLS, read ? TLS_RX : TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
        perror("setsockopt");
        return false;
    }

    return true;
}

bool setup_ktls(int client) {
    bool success = false;

    mbedtls_ctr_drbg_reseed(&ctr_drbg, NULL, 0);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    mbedtls_ssl_conf_ciphersuites(&conf, AES_128_CIPHERS);
    ENSURE(mbedtls_ssl_setup(&ssl, &conf));

    mbedtls_ssl_set_bio(&ssl, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            PRINT_MBEDTLS_ERROR(ret);
            goto cleanup;
        }
    }

    if (setsockopt(client, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        perror("setsockopt");
        goto cleanup;
    }

    success = set_crypto_info(client, &ssl, true) &&
              set_crypto_info(client, &ssl, false);

cleanup:
    mbedtls_ssl_free(&ssl);
    return success;
}

__attribute__((constructor))
static void init(void) {
    real_bind    = dlsym(RTLD_NEXT, "bind");
    real_accept  = dlsym(RTLD_NEXT, "accept");
    real_accept4 = dlsym(RTLD_NEXT, "accept4");

    cert = getenv("KTLS_WRAPPER_CERT");
    key  = getenv("KTLS_WRAPPER_KEY");
    char *port_str = getenv("KTLS_WRAPPER_PORT");

    if (!port_str || !cert || !key) {
        fprintf(stderr, "KTLS_WRAPPER_CERT, KTLS_WRAPPER_KEY or KTLS_WRAPPER_PORT missing.\n");
        return;
    }

    port = htons(atoi(port_str));

    init_ssl_conf();
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = real_bind(sockfd, addr, addrlen);
    if (ret == 0 &&
        addr->sa_family == AF_INET &&
        ((const struct sockaddr_in *) addr)->sin_port == port) {
        target_sockfd = sockfd;
    }

    return ret;
}

#define SETUP_TLS(client) \
{ \
    if ((client) >= 0 && sockfd == target_sockfd) { \
        if (!setup_ktls((client))) { \
            close((client)); \
            return -ECONNABORTED; \
        } \
    } \
    return client; \
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int client = real_accept(sockfd, addr, addrlen);
    SETUP_TLS(client);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    int client = real_accept4(sockfd, addr, addrlen, flags);
    SETUP_TLS(client);
}

