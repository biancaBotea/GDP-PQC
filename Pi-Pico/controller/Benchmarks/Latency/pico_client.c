#include <string.h>
#include <time.h>

#include "hardware/structs/rosc.h"
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"

//#define PICO_LATENCY
//#define PICO_CYCLES_BREAKDOWN
#define PICO_CYCLES_OVERALL
#if defined(PICO_LATENCY)|| \
    defined(PICO_CYCLES_BREAKDOWN)|| \
    defined(PICO_CYCLES_OVERALL)
#include "pqc-pico/utimer.h"
#include "pqc-pico/systick.h"
#endif


#define TLS_CLIENT_TIMEOUT_SECS  90
#define DFL_SERVER_PORT 4433
#define SERVER_IP 192,168,1,87

char* serverIP = "";
char* msgToServer = "";
int timer_init = 0;

#define DEBUG_LEVEL 0

#define PRINT_AT_DEBUG_LEVEL(level, msg) \
    if (DEBUG_LEVEL >= level) printf(msg)

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
     */
     
    u_int32_t flags;
    PRINT_AT_DEBUG_LEVEL(1, "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( altcp_tls_context(state->pcb) ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed verify\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
    }
    else
        PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );
        

    //printf("connected to server, sending request\n");
    err = altcp_write(state->pcb, msgToServer, strlen(msgToServer), TCP_WRITE_FLAG_COPY);
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
        PRINT_AT_DEBUG_LEVEL(1,"connection closed\n");
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
        if(DEBUG_LEVEL >= 1)
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

    if(DEBUG_LEVEL >= 1)
        printf("connecting to server IP %s port %d\n", ipaddr_ntoa(ipaddr), port);
    err = altcp_connect(state->pcb, ipaddr, port, tls_client_connected);
    if (err != ERR_OK)
    {
        fprintf(stderr, "error initiating connect, err=%d\n", err);
        tls_client_close(state);
    }
}

static bool tls_client_open(ip_addr_t server_ip, void *arg) {
    err_t err;
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
    //mbedtls_ssl_set_hostname(altcp_tls_context(state->pcb), hostname);

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

mbedtls_pq_performance run_client(const ip_addr_t server_ip, const char *cert, char *msg) {
    /* No CA certificate checking */
    //tls_config = altcp_tls_create_config_client();
    
    /* With CA certificate checking */

    /*printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );
    int ret = 0;
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_ca_crt,
		mbedtls_test_ca_crt_len);
	if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
    }
    else{
        printf( " ok (%d skipped)\n", ret );
    }
    */
    msgToServer = msg;
    
    tls_config = altcp_tls_create_config_client((const unsigned char *) cert, strlen(cert) + 1);
    
#if defined(PICO_LATENCY)
    // start the overall latency timer

    microsecond_count_t* utp = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));
    init_utimer(utp);

    //printf("Begin utimer\n");
    begin_utimer(utp);
#elif defined(PICO_CYCLES_OVERALL)
    // start the overall latency timer
    init_systick_reg();
    systick_count_t* stp = (systick_count_t*) malloc(sizeof(systick_count_t));
    init_systick(stp);
    begin_systick(stp);
            
#endif

    TLS_CLIENT_T *state = tls_client_init();
    if (!state) {
        return;
    }
    if (!tls_client_open(server_ip, state)) {
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
        //sleep_ms(1000);
        sleep_ms(100);
#endif
    }
#if defined(PICO_LATENCY)
    // end the overall latency timer
    //printf("End utimer\n");
    end_utimer(utp);
    double overall_handshake = (double)utp->ut_diff /1000.0;
    //printf("\nOverall latency = %llu\n",utp->ut_diff);
    free_utimer(utp);
    mbedtls_pq_performance performance = get_mbedtls_pq_performance();
    performance.handshake = overall_handshake;
#elif defined(PICO_CYCLES_BREAKDOWN)
    // end cycle counter
    mbedtls_pq_performance performance = get_mbedtls_pq_performance();
    if(DEBUG_LEVEL >= 1){
        printf("\nKEM Cycles = %f\n",performance.kyber_enc);
        printf("\nSIG Cycles = %f\n",performance.sphincs_verify);
    }

    performance.handshake = 0.0;
#elif defined(PICO_CYCLES_OVERALL)
    // end cycle counter
    end_systick(stp);
    double overall_handshake = (double)stp->st_diff;
    free_systick(stp);
    mbedtls_pq_performance performance;

    performance.handshake = overall_handshake;      
#endif
    free(state);
    altcp_tls_free_config(tls_config);
    fflush(stdout);
    return performance;
}

