/* Benchmark.c
 * 
 * An application to automate the benchmarking of post 
 * quantum cryptographic algorithms. The application
 * measures a series of TLS 1.3 handshakes in order to
 * analyse memory usage.
 * 
 * This application was writted as part of the Group
 * Design Project 2022 at the University of Southampton,
 * in partnership with DSTL.
 * 
 * ------- IMPORTANT -------
 * For heap usage results to show the correct defines
 * must be applied in config.h and GDP_MEM_TEST must
 * be defined in ssl_client1.c
 */


#include "pico/stdlib.h"
#include "pico/time.h"
#include <string.h>
#include <unistd.h>
#include <math.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

/* extra src files */
#include "./pico_client.h"
#include "./new_certs.h"
#include "mbedtls/ssl.h"
#include <time.h>

#include "hardware/structs/rosc.h"
#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"

#define TEST_SIZE	30

double calc_std_dev(double x, double x2, int n) {
	double mean = x / n;
	double variance = x2 / n - pow(mean, 2);
	double std_dev = sqrt(variance);
	return std_dev;
}

/* application args */
const char *cert = TEST_CA_CRT_DILITHIUM_SHAKE256_PEM;
char * MsgToServer = "Test Message";

ip_addr_t server_ip;

int main() {
	stdio_init_all();
	sleep_ms(5000);
	printf("*** Running TLS client - Latency Benchmark ***\n");
	printf("MEM_SIZE = %d\n", MEM_SIZE);
	printf("Connecting to WiFi: %s, %s\n", WIFI_SSID, WIFI_PASSWORD); 
	if (cyw43_arch_init_with_country(CYW43_COUNTRY_UK)) {
	printf("failed to initialise\n");
	return 1;
	}
	cyw43_arch_enable_sta_mode();
	int ret = cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 300000);	
	if (ret) {
	printf("failed to connect %d\n", ret);
	return 1;
	}
	printf("Connected.\n");
	cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);
	IP4_ADDR(&server_ip,192,168,12,26);

	// Wait for server to start
	sleep_ms(5000);
	
	// Loop for a given number of handshakes
	for (int j = 0; j < TEST_SIZE; j++) {
		run_client(server_ip, cert, MsgToServer);
		sleep_ms(500);
	}

	// Shutdown the server
	run_client(server_ip, cert, "Shutdown");

	printf("Finished.\n");
	/* sleep a bit to let usb stdio write out any buffer to host */
	sleep_ms(100);

	cyw43_arch_deinit();
  	return 0;
}
