#include <string.h>
#include <time.h>

#include "hardware/structs/rosc.h"
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"

//#include "mbedtls/certs.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#define TLS_CLIENT_SERVER        "localhost"
#define TLS_CLIENT_HTTP_REQUEST  "GET / HTTP/1.0\r\n\r\n"//"GET %s HTTP/1.0\r\nExtra-header: "
#define TLS_CLIENT_TIMEOUT_SECS  90

#define DFL_SERVER_ADDR         "10.9.19.29"
#define DFL_SERVER_PORT         4433

#define DEBUG_LEVEL 4

#define TEST_CA_CRT_SPHINCS_SHAKE256_PEM                                \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    printf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

typedef struct TLS_CLIENT_T_ {
    struct altcp_pcb *pcb;
    bool complete;
} TLS_CLIENT_T;

static struct altcp_tls_config *tls_config = NULL;


/* Function to feed mbedtls entropy. May be better to move it to pico-sdk */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    /* Code borrowed from pico_lwip_random_byte(), which is static, so we cannot call it directly */
    static uint8_t byte;

    for(int p=0; p<len; p++) {
        for(int i=0;i<32;i++) {
            // picked a fairly arbitrary polynomial of 0x35u - this doesn't have to be crazily uniform.
            byte = ((byte << 1) | rosc_hw->randombit) ^ (byte & 0x80u ? 0x35u : 0);
            // delay a little because the random bit is a little slow
            busy_wait_at_least_cycles(30);
        }
        output[p] = byte;
    }

    *olen = len;
    return 0;
}


static err_t tls_client_close(void *arg) {
    TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
    err_t err = ERR_OK;

    state->complete = true;
    if (state->pcb != NULL) {
        altcp_arg(state->pcb, NULL);
        altcp_poll(state->pcb, NULL, 0);
        altcp_recv(state->pcb, NULL);
        altcp_err(state->pcb, NULL);
        err = altcp_close(state->pcb);
        if (err != ERR_OK) {
            printf("close failed %d, calling abort\n", err);
            altcp_abort(state->pcb);
            err = ERR_ABRT;
        }
        state->pcb = NULL;
    }
    return err;
}

static err_t tls_client_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
    TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
    if (err != ERR_OK) {
        printf("connect failed %d\n", err);
        return tls_client_close(state);
    }
    
    /*
     * Verify the server certificate
     * Currently yields error: 
     * "! The certificate is not correctly signed by the trusted CA"
     */
     
    uint32_t flags;
    
    printf( "  . Verifying peer X.509 certificate..." );

    if( ( flags = mbedtls_ssl_get_verify_result( altcp_tls_context(state->pcb) ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
    }
    else
        printf( " ok\n" );

    
    printf("connected to server, sending request\n");
    err = altcp_write(state->pcb, TLS_CLIENT_HTTP_REQUEST, strlen(TLS_CLIENT_HTTP_REQUEST), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        printf("error writing data, err=%d", err);
        return tls_client_close(state);
    }

    return ERR_OK;
}

static err_t tls_client_poll(void *arg, struct altcp_pcb *pcb) {
    printf("timed out");
    return tls_client_close(arg);
}

static void tls_client_err(void *arg, err_t err) {
    TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
    printf("tls_client_err %d\n", err);
    state->pcb = NULL; /* pcb freed by lwip when _err function is called */
}

static err_t tls_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
    TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
    if (!p) {
        printf("connection closed\n");
        return tls_client_close(state);
    }

    if (p->tot_len > 0) {
        /* For simplicity this examples creates a buffer on stack the size of the data pending here, 
           and copies all the data to it in one go.
           Do be aware that the amount of data can potentially be a bit large (TLS record size can be 16 KB),
           so you may want to use a smaller fixed size buffer and copy the data to it using a loop, if memory is a concern */
        char buf[p->tot_len + 1];

        pbuf_copy_partial(p, buf, p->tot_len, 0);
        buf[p->tot_len] = 0;

        printf("***\nnew data received from server:\n***\n\n%s\n", buf);

        altcp_recved(pcb, p->tot_len);
    }
    pbuf_free(p);

    return ERR_OK;
}

static void tls_client_connect_to_server_ip(const ip_addr_t *ipaddr, TLS_CLIENT_T *state)
{
    err_t err;
    u16_t port = DFL_SERVER_PORT;

    printf("connecting to server IP %s port %d\n", ipaddr_ntoa(ipaddr), port);
    err = altcp_connect(state->pcb, ipaddr, port, tls_client_connected);
    if (err != ERR_OK)
    {
        fprintf(stderr, "error initiating connect, err=%d\n", err);
        tls_client_close(state);
    } else {
        printf("connected\n");
    }
}

static bool tls_client_open(const char *hostname, void *arg) {
    err_t err;
    ip_addr_t server_ip;
    IP4_ADDR(&server_ip,10,9,19,29);
    TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;

    state->pcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
    if (!state->pcb) {
        printf("failed to create pcb\n");
        return false;
    }

    altcp_arg(state->pcb, state);
    altcp_poll(state->pcb, tls_client_poll, TLS_CLIENT_TIMEOUT_SECS * 2);
    altcp_recv(state->pcb, tls_client_recv);
    altcp_err(state->pcb, tls_client_err);

    /* Set SNI */
    mbedtls_ssl_set_hostname(altcp_tls_context(state->pcb), hostname);

    printf("resolving %s\n", hostname);

    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();

    tls_client_connect_to_server_ip(&server_ip, state);

    cyw43_arch_lwip_end();

    return err == ERR_OK || err == ERR_INPROGRESS;
}

// Perform initialisation
static TLS_CLIENT_T* tls_client_init(void) {
    TLS_CLIENT_T *state = calloc(1, sizeof(TLS_CLIENT_T));
    if (!state) {
        printf("failed to allocate state\n");
        return NULL;
    }

    return state;
}

void run_TLS_CLIENT_Test(void) {

    
    /* Load CA cert
     * Could include certs.h and comment following three lines
     */
    static const char test_ca_crt[] = TEST_CA_CRT_SPHINCS_SHAKE256_PEM;
    const char *mbedtls_test_ca_crt = test_ca_crt;
    const size_t mbedtls_test_ca_crt_len = sizeof( test_ca_crt );
    
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init( &cacert );

    printf( "  . Loading the CA root certificate ..." );

    int ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_ca_crt,
		mbedtls_test_ca_crt_len);
	if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        while (1) {}
    }

    printf( " ok (%d skipped)\n", ret );
    
    /* Create config with cert
     */
    tls_config = altcp_tls_create_config_client((const unsigned char *)mbedtls_test_ca_crt, mbedtls_test_ca_crt_len);
    
    /* No CA certificate checking */
    //tls_config = altcp_tls_create_config_client(NULL, 0);
    
    
    TLS_CLIENT_T *state = tls_client_init();
    if (!state) {
        return;
    }
    if (!tls_client_open(TLS_CLIENT_SERVER, state)) {
        return;
    }
    while(!state->complete) {
        // the following #ifdef is only here so this same example can be used in multiple modes;
        // you do not need it in your code
#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer) to check for WiFi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        sleep_ms(1);
#else
        // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(1000);
#endif
    }
    free(state);
    altcp_tls_free_config(tls_config);
}

int main() {
    stdio_init_all();
    sleep_ms(5000);
    mbedtls_ssl_config conf;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif
    //mbedtls_ssl_config_init( &conf );
    //mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    printf("Running TLS client, mem: %d\n", MEM_SIZE);
    printf("Connecting to WiFi: %s, %s\n", WIFI_SSID, WIFI_PASSWORD); 
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();
    int ret = cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000);	
    if (ret) {
        printf("failed to connect %d\n", ret);
        return 1;
    }
    run_TLS_CLIENT_Test();

    /* sleep a bit to let usb stdio write out any buffer to host */
    sleep_ms(100);

    cyw43_arch_deinit();
    return 0;
}




