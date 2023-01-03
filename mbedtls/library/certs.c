/*
 *  X.509 test certificates
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/certs.h"

#if defined(MBEDTLS_CERTS_C)

/*
 * Test CA Certificates
 *
 * We define test CA certificates for each choice of the following parameters:
 * - PEM or DER encoding
 * - SHA-1 or SHA-256 hash
 * - RSA or EC key
 *
 * Things to add:
 * - multiple EC curve types
 *
 */

/* This is taken from tests/data_files/test-ca2.crt */
/* BEGIN FILE string macro TEST_CA_CRT_EC_PEM tests/data_files/test-ca2.crt */
#define TEST_CA_CRT_EC_PEM                                                 \
  "-----BEGIN CERTIFICATE-----\r\n"	\
  "MIICOTCCAZmgAwIBAgIBATAMBggqhkjOPQQDAgUAMDYxGTAXBgNVBAMMEFJvb3Qg\r\n"	\
  "Q2VydGlmaWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswHhcNMjIwMTAx\r\n"	\
  "MDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA2MRkwFwYDVQQDDBBSb290IENlcnRpZmlj\r\n"	\
  "YXRlMQwwCgYDVQQKDANVb1MxCzAJBgNVBAYTAlVLMIGbMBAGByqGSM49AgEGBSuB\r\n"	\
  "BAAjA4GGAAQAUGUOZfOnbF7C13vbZ5GBTo+0L7SARkvYoAxVowH3ukevnRcR/0oE\r\n"	\
  "CgElNAf7ySlOKYnztnLpsU2580X133RVykcBrzBnjkTvcXNRfTVZtdZcvyGpSbNC\r\n"	\
  "gP+495/gqNY5Hx4j5HnNJtyUoHliFzTnyDI+YjlEWrTHxVmFqWcSbeAPwTOjUzBR\r\n"	\
  "MA8GA1UdEwQIMAYBAf8CAQAwHQYDVR0OBBYEFMzm7Zvhd0Uk2cl/IYGuC0ANtQvC\r\n"	\
  "MB8GA1UdIwQYMBaAFMzm7Zvhd0Uk2cl/IYGuC0ANtQvCMAwGCCqGSM49BAMCBQAD\r\n"	\
  "gYsAMIGHAkIA2Zc10EnLY+dBKiaE7+cQMdxIN2RaRWxVyDqr0AjH5dndiDppzqiv\r\n"	\
  "EKT7oVm4pHYPrsrM3CHbrOYWkanugutCQuACQSntrj6Pcjow0quXPMcZt+OFrodl\r\n"	\
  "DNpjDH77Pr0NX2W1pFNY0TUT2tmTyaw+eta3PYnFnSDr6irGphITNMN0Qwq5\r\n"	\
  "-----END CERTIFICATE-----\r\n"	  
/* END FILE */

/* This is generated from tests/data_files/test-ca2.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_CRT_EC_DER tests/data_files/test-ca2.crt.der */
#define TEST_CA_CRT_EC_DER {                                                 \
  0x30, 0x82, 0x02, 0x04, 0x30, 0x82, 0x01, 0x88, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x09, 0x00, 0xc1, 0x43, 0xe2, 0x7e, 0x62, 0x43, 0xcc, 0xe8,    \
  0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,    \
  0x05, 0x00, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,    \
  0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,    \
  0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x50,    \
  0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65, 0x73, 0x74,    \
  0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39,    \
  0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30, 0x5a, 0x17,    \
  0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30,    \
  0x30, 0x5a, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,    \
  0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55,    \
  0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x50,    \
  0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65, 0x73, 0x74,    \
  0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07,    \
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,    \
  0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xc3, 0xda, 0x2b, 0x34, 0x41, 0x37,    \
  0x58, 0x2f, 0x87, 0x56, 0xfe, 0xfc, 0x89, 0xba, 0x29, 0x43, 0x4b, 0x4e,    \
  0xe0, 0x6e, 0xc3, 0x0e, 0x57, 0x53, 0x33, 0x39, 0x58, 0xd4, 0x52, 0xb4,    \
  0x91, 0x95, 0x39, 0x0b, 0x23, 0xdf, 0x5f, 0x17, 0x24, 0x62, 0x48, 0xfc,    \
  0x1a, 0x95, 0x29, 0xce, 0x2c, 0x2d, 0x87, 0xc2, 0x88, 0x52, 0x80, 0xaf,    \
  0xd6, 0x6a, 0xab, 0x21, 0xdd, 0xb8, 0xd3, 0x1c, 0x6e, 0x58, 0xb8, 0xca,    \
  0xe8, 0xb2, 0x69, 0x8e, 0xf3, 0x41, 0xad, 0x29, 0xc3, 0xb4, 0x5f, 0x75,    \
  0xa7, 0x47, 0x6f, 0xd5, 0x19, 0x29, 0x55, 0x69, 0x9a, 0x53, 0x3b, 0x20,    \
  0xb4, 0x66, 0x16, 0x60, 0x33, 0x1e, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c,    \
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,    \
  0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x9d,    \
  0x6d, 0x20, 0x24, 0x49, 0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc,    \
  0x7e, 0x24, 0xc9, 0xdb, 0xfb, 0x36, 0x7c, 0x30, 0x1f, 0x06, 0x03, 0x55,    \
  0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24,    \
  0x49, 0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9,    \
  0xdb, 0xfb, 0x36, 0x7c, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,    \
  0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02,    \
  0x30, 0x51, 0xca, 0xae, 0x30, 0x0f, 0xa4, 0x70, 0x74, 0x04, 0xdd, 0x5a,    \
  0x2c, 0x7f, 0x13, 0xc1, 0xc2, 0x77, 0xbe, 0x1d, 0x00, 0xc5, 0xe2, 0x99,    \
  0x8f, 0x7d, 0x26, 0x45, 0xd3, 0x8a, 0x06, 0x68, 0x3f, 0x8c, 0xb4, 0xb7,    \
  0xad, 0x4d, 0xe0, 0xf1, 0x54, 0x01, 0x1e, 0x99, 0xfc, 0xb0, 0xe4, 0xd3,    \
  0x07, 0x02, 0x31, 0x00, 0xdc, 0x4f, 0x3b, 0x90, 0x1e, 0xae, 0x29, 0x99,    \
  0x84, 0x28, 0xcc, 0x7b, 0x47, 0x78, 0x09, 0x31, 0xdf, 0xd6, 0x01, 0x59,    \
  0x30, 0x5e, 0xf4, 0xf8, 0x8a, 0x84, 0x3f, 0xea, 0x39, 0x54, 0x7b, 0x08,    \
  0xa7, 0x60, 0xaa, 0xbd, 0xf9, 0x5b, 0xd1, 0x51, 0x96, 0x14, 0x2e, 0x65,    \
  0xf5, 0xae, 0x1c, 0x42                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca2.key.enc */
/* BEGIN FILE string macro TEST_CA_KEY_EC_PEM tests/data_files/test-ca2.key.enc */
#define TEST_CA_KEY_EC_PEM                                                 \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "Proc-Type: 4,ENCRYPTED\r\n"                                           \
    "DEK-Info: DES-EDE3-CBC,307EAB469933D64E\r\n"                          \
    "\r\n"                                                                 \
    "IxbrRmKcAzctJqPdTQLA4SWyBYYGYJVkYEna+F7Pa5t5Yg/gKADrFKcm6B72e7DG\r\n" \
    "ihExtZI648s0zdYw6qSJ74vrPSuWDe5qm93BqsfVH9svtCzWHW0pm1p0KTBCFfUq\r\n" \
    "UsuWTITwJImcnlAs1gaRZ3sAWm7cOUidL0fo2G0fYUFNcYoCSLffCFTEHBuPnagb\r\n" \
    "a77x/sY1Bvii8S9/XhDTb6pTMx06wzrm\r\n"                                 \
    "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

#define TEST_CA_PWD_EC_PEM "PolarSSLTest"

/* This is generated from tests/data_files/test-ca2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_KEY_EC_DER tests/data_files/test-ca2.key.der */
#define TEST_CA_KEY_EC_DER {                                                 \
    0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x83, 0xd9, 0x15, 0x0e,  \
    0xa0, 0x71, 0xf0, 0x57, 0x10, 0x33, 0xa3, 0x38, 0xb8, 0x86, 0xc1, 0xa6,  \
    0x11, 0x5d, 0x6d, 0xb4, 0x03, 0xe1, 0x29, 0x76, 0x45, 0xd7, 0x87, 0x6f,  \
    0x23, 0xab, 0x44, 0x20, 0xea, 0x64, 0x7b, 0x85, 0xb1, 0x76, 0xe7, 0x85,  \
    0x95, 0xaa, 0x74, 0xd6, 0xd1, 0xa4, 0x5e, 0xea, 0xa0, 0x07, 0x06, 0x05,  \
    0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xc3,  \
    0xda, 0x2b, 0x34, 0x41, 0x37, 0x58, 0x2f, 0x87, 0x56, 0xfe, 0xfc, 0x89,  \
    0xba, 0x29, 0x43, 0x4b, 0x4e, 0xe0, 0x6e, 0xc3, 0x0e, 0x57, 0x53, 0x33,  \
    0x39, 0x58, 0xd4, 0x52, 0xb4, 0x91, 0x95, 0x39, 0x0b, 0x23, 0xdf, 0x5f,  \
    0x17, 0x24, 0x62, 0x48, 0xfc, 0x1a, 0x95, 0x29, 0xce, 0x2c, 0x2d, 0x87,  \
    0xc2, 0x88, 0x52, 0x80, 0xaf, 0xd6, 0x6a, 0xab, 0x21, 0xdd, 0xb8, 0xd3,  \
    0x1c, 0x6e, 0x58, 0xb8, 0xca, 0xe8, 0xb2, 0x69, 0x8e, 0xf3, 0x41, 0xad,  \
    0x29, 0xc3, 0xb4, 0x5f, 0x75, 0xa7, 0x47, 0x6f, 0xd5, 0x19, 0x29, 0x55,  \
    0x69, 0x9a, 0x53, 0x3b, 0x20, 0xb4, 0x66, 0x16, 0x60, 0x33, 0x1e         \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha256.crt. */
/* BEGIN FILE string macro TEST_CA_CRT_RSA_SHA256_PEM tests/data_files/test-ca-sha256.crt */
#define TEST_CA_CRT_RSA_SHA256_PEM                                         \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDQTCCAimgAwIBAgIBAzANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDAwWhcNMjkwMjEwMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n" \
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n" \
    "mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n" \
    "50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n" \
    "YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n" \
    "R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n" \
    "KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n" \
    "UDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFLRa5KWz3tJS9rnVppUP6z68x/3/\r\n" \
    "MB8GA1UdIwQYMBaAFLRa5KWz3tJS9rnVppUP6z68x/3/MA0GCSqGSIb3DQEBCwUA\r\n" \
    "A4IBAQA4qFSCth2q22uJIdE4KGHJsJjVEfw2/xn+MkTvCMfxVrvmRvqCtjE4tKDl\r\n" \
    "oK4MxFOek07oDZwvtAT9ijn1hHftTNS7RH9zd/fxNpfcHnMZXVC4w4DNA1fSANtW\r\n" \
    "5sY1JB5Je9jScrsLSS+mAjyv0Ow3Hb2Bix8wu7xNNrV5fIf7Ubm+wt6SqEBxu3Kb\r\n" \
    "+EfObAT4huf3czznhH3C17ed6NSbXwoXfby7stWUDeRJv08RaFOykf/Aae7bY5PL\r\n" \
    "yTVrkAnikMntJ9YI+hNNYt3inqq11A5cN0+rVTst8UKCxzQ4GpvroSwPKTFkbMw4\r\n" \
    "/anT1dVxr/BtwJfiESoK3/4CeXR1\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/test-ca-sha256.crt.der
 * using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_CRT_RSA_SHA256_DER tests/data_files/test-ca-sha256.crt.der */
#define TEST_CA_CRT_RSA_SHA256_DER {                                         \
  0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x30, 0x5a, 0x30, 0x3b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x54, 0x65,    \
  0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,    \
  0x01, 0x00, 0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f,    \
  0x86, 0xde, 0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1,    \
  0x99, 0xd4, 0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec,    \
  0x9b, 0xc5, 0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b,    \
  0xc0, 0x8d, 0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9,    \
  0x93, 0xe8, 0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2,    \
  0xe7, 0x40, 0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40,    \
  0xf9, 0x3e, 0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8,    \
  0x29, 0x00, 0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1,    \
  0xbd, 0x83, 0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27,    \
  0x60, 0xc3, 0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84,    \
  0x32, 0xbe, 0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5,    \
  0xfb, 0xf5, 0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e,    \
  0xee, 0xe2, 0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb,    \
  0x47, 0xb1, 0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab,    \
  0xf1, 0x79, 0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62,    \
  0x6f, 0x27, 0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37,    \
  0xa1, 0x30, 0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e,    \
  0x28, 0xd1, 0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64,    \
  0x09, 0xea, 0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b,    \
  0xc9, 0xab, 0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32,    \
  0x9e, 0x99, 0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,    \
  0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,    \
  0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,    \
  0x04, 0x16, 0x04, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52,    \
  0xf6, 0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff,    \
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,    \
  0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5,    \
  0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x01, 0x00, 0x38, 0xa8, 0x54, 0x82, 0xb6, 0x1d, 0xaa,    \
  0xdb, 0x6b, 0x89, 0x21, 0xd1, 0x38, 0x28, 0x61, 0xc9, 0xb0, 0x98, 0xd5,    \
  0x11, 0xfc, 0x36, 0xff, 0x19, 0xfe, 0x32, 0x44, 0xef, 0x08, 0xc7, 0xf1,    \
  0x56, 0xbb, 0xe6, 0x46, 0xfa, 0x82, 0xb6, 0x31, 0x38, 0xb4, 0xa0, 0xe5,    \
  0xa0, 0xae, 0x0c, 0xc4, 0x53, 0x9e, 0x93, 0x4e, 0xe8, 0x0d, 0x9c, 0x2f,    \
  0xb4, 0x04, 0xfd, 0x8a, 0x39, 0xf5, 0x84, 0x77, 0xed, 0x4c, 0xd4, 0xbb,    \
  0x44, 0x7f, 0x73, 0x77, 0xf7, 0xf1, 0x36, 0x97, 0xdc, 0x1e, 0x73, 0x19,    \
  0x5d, 0x50, 0xb8, 0xc3, 0x80, 0xcd, 0x03, 0x57, 0xd2, 0x00, 0xdb, 0x56,    \
  0xe6, 0xc6, 0x35, 0x24, 0x1e, 0x49, 0x7b, 0xd8, 0xd2, 0x72, 0xbb, 0x0b,    \
  0x49, 0x2f, 0xa6, 0x02, 0x3c, 0xaf, 0xd0, 0xec, 0x37, 0x1d, 0xbd, 0x81,    \
  0x8b, 0x1f, 0x30, 0xbb, 0xbc, 0x4d, 0x36, 0xb5, 0x79, 0x7c, 0x87, 0xfb,    \
  0x51, 0xb9, 0xbe, 0xc2, 0xde, 0x92, 0xa8, 0x40, 0x71, 0xbb, 0x72, 0x9b,    \
  0xf8, 0x47, 0xce, 0x6c, 0x04, 0xf8, 0x86, 0xe7, 0xf7, 0x73, 0x3c, 0xe7,    \
  0x84, 0x7d, 0xc2, 0xd7, 0xb7, 0x9d, 0xe8, 0xd4, 0x9b, 0x5f, 0x0a, 0x17,    \
  0x7d, 0xbc, 0xbb, 0xb2, 0xd5, 0x94, 0x0d, 0xe4, 0x49, 0xbf, 0x4f, 0x11,    \
  0x68, 0x53, 0xb2, 0x91, 0xff, 0xc0, 0x69, 0xee, 0xdb, 0x63, 0x93, 0xcb,    \
  0xc9, 0x35, 0x6b, 0x90, 0x09, 0xe2, 0x90, 0xc9, 0xed, 0x27, 0xd6, 0x08,    \
  0xfa, 0x13, 0x4d, 0x62, 0xdd, 0xe2, 0x9e, 0xaa, 0xb5, 0xd4, 0x0e, 0x5c,    \
  0x37, 0x4f, 0xab, 0x55, 0x3b, 0x2d, 0xf1, 0x42, 0x82, 0xc7, 0x34, 0x38,    \
  0x1a, 0x9b, 0xeb, 0xa1, 0x2c, 0x0f, 0x29, 0x31, 0x64, 0x6c, 0xcc, 0x38,    \
  0xfd, 0xa9, 0xd3, 0xd5, 0xd5, 0x71, 0xaf, 0xf0, 0x6d, 0xc0, 0x97, 0xe2,    \
  0x11, 0x2a, 0x0a, 0xdf, 0xfe, 0x02, 0x79, 0x74, 0x75                       \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha1.crt. */
/* BEGIN FILE string macro TEST_CA_CRT_RSA_SHA1_PEM tests/data_files/test-ca-sha1.crt */
#define TEST_CA_CRT_RSA_SHA1_PEM                                           \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDQTCCAimgAwIBAgIBAzANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDAwWhcNMjkwMjEwMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n" \
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n" \
    "mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n" \
    "50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n" \
    "YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n" \
    "R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n" \
    "KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n" \
    "UDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFLRa5KWz3tJS9rnVppUP6z68x/3/\r\n" \
    "MB8GA1UdIwQYMBaAFLRa5KWz3tJS9rnVppUP6z68x/3/MA0GCSqGSIb3DQEBBQUA\r\n" \
    "A4IBAQB0ZiNRFdia6kskaPnhrqejIRq8YMEGAf2oIPnyZ78xoyERgc35lHGyMtsL\r\n" \
    "hWicNjP4d/hS9As4j5KA2gdNGi5ETA1X7SowWOGsryivSpMSHVy1+HdfWlsYQOzm\r\n" \
    "8o+faQNUm8XzPVmttfAVspxeHSxJZ36Oo+QWZ5wZlCIEyjEdLUId+Tm4Bz3B5jRD\r\n" \
    "zZa/SaqDokq66N2zpbgKKAl3GU2O++fBqP2dSkdQykmTxhLLWRN8FJqhYATyQntZ\r\n" \
    "0QSi3W9HfSZPnFTcPIXeoiPd2pLlxt1hZu8dws2LTXE63uP6MM4LHvWxiuJaWkP/\r\n" \
    "mtxyUALj2pQxRitopORFQdn7AOY5\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/test-ca-sha1.crt.der. */
/* BEGIN FILE binary macro TEST_CA_CRT_RSA_SHA1_DER tests/data_files/test-ca-sha1.crt.der */
#define TEST_CA_CRT_RSA_SHA1_DER {                                           \
  0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x30, 0x5a, 0x30, 0x3b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x54, 0x65,    \
  0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,    \
  0x01, 0x00, 0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f,    \
  0x86, 0xde, 0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1,    \
  0x99, 0xd4, 0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec,    \
  0x9b, 0xc5, 0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b,    \
  0xc0, 0x8d, 0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9,    \
  0x93, 0xe8, 0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2,    \
  0xe7, 0x40, 0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40,    \
  0xf9, 0x3e, 0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8,    \
  0x29, 0x00, 0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1,    \
  0xbd, 0x83, 0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27,    \
  0x60, 0xc3, 0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84,    \
  0x32, 0xbe, 0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5,    \
  0xfb, 0xf5, 0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e,    \
  0xee, 0xe2, 0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb,    \
  0x47, 0xb1, 0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab,    \
  0xf1, 0x79, 0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62,    \
  0x6f, 0x27, 0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37,    \
  0xa1, 0x30, 0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e,    \
  0x28, 0xd1, 0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64,    \
  0x09, 0xea, 0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b,    \
  0xc9, 0xab, 0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32,    \
  0x9e, 0x99, 0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,    \
  0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,    \
  0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,    \
  0x04, 0x16, 0x04, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52,    \
  0xf6, 0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff,    \
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,    \
  0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5,    \
  0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06,    \
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,    \
  0x03, 0x82, 0x01, 0x01, 0x00, 0x74, 0x66, 0x23, 0x51, 0x15, 0xd8, 0x9a,    \
  0xea, 0x4b, 0x24, 0x68, 0xf9, 0xe1, 0xae, 0xa7, 0xa3, 0x21, 0x1a, 0xbc,    \
  0x60, 0xc1, 0x06, 0x01, 0xfd, 0xa8, 0x20, 0xf9, 0xf2, 0x67, 0xbf, 0x31,    \
  0xa3, 0x21, 0x11, 0x81, 0xcd, 0xf9, 0x94, 0x71, 0xb2, 0x32, 0xdb, 0x0b,    \
  0x85, 0x68, 0x9c, 0x36, 0x33, 0xf8, 0x77, 0xf8, 0x52, 0xf4, 0x0b, 0x38,    \
  0x8f, 0x92, 0x80, 0xda, 0x07, 0x4d, 0x1a, 0x2e, 0x44, 0x4c, 0x0d, 0x57,    \
  0xed, 0x2a, 0x30, 0x58, 0xe1, 0xac, 0xaf, 0x28, 0xaf, 0x4a, 0x93, 0x12,    \
  0x1d, 0x5c, 0xb5, 0xf8, 0x77, 0x5f, 0x5a, 0x5b, 0x18, 0x40, 0xec, 0xe6,    \
  0xf2, 0x8f, 0x9f, 0x69, 0x03, 0x54, 0x9b, 0xc5, 0xf3, 0x3d, 0x59, 0xad,    \
  0xb5, 0xf0, 0x15, 0xb2, 0x9c, 0x5e, 0x1d, 0x2c, 0x49, 0x67, 0x7e, 0x8e,    \
  0xa3, 0xe4, 0x16, 0x67, 0x9c, 0x19, 0x94, 0x22, 0x04, 0xca, 0x31, 0x1d,    \
  0x2d, 0x42, 0x1d, 0xf9, 0x39, 0xb8, 0x07, 0x3d, 0xc1, 0xe6, 0x34, 0x43,    \
  0xcd, 0x96, 0xbf, 0x49, 0xaa, 0x83, 0xa2, 0x4a, 0xba, 0xe8, 0xdd, 0xb3,    \
  0xa5, 0xb8, 0x0a, 0x28, 0x09, 0x77, 0x19, 0x4d, 0x8e, 0xfb, 0xe7, 0xc1,    \
  0xa8, 0xfd, 0x9d, 0x4a, 0x47, 0x50, 0xca, 0x49, 0x93, 0xc6, 0x12, 0xcb,    \
  0x59, 0x13, 0x7c, 0x14, 0x9a, 0xa1, 0x60, 0x04, 0xf2, 0x42, 0x7b, 0x59,    \
  0xd1, 0x04, 0xa2, 0xdd, 0x6f, 0x47, 0x7d, 0x26, 0x4f, 0x9c, 0x54, 0xdc,    \
  0x3c, 0x85, 0xde, 0xa2, 0x23, 0xdd, 0xda, 0x92, 0xe5, 0xc6, 0xdd, 0x61,    \
  0x66, 0xef, 0x1d, 0xc2, 0xcd, 0x8b, 0x4d, 0x71, 0x3a, 0xde, 0xe3, 0xfa,    \
  0x30, 0xce, 0x0b, 0x1e, 0xf5, 0xb1, 0x8a, 0xe2, 0x5a, 0x5a, 0x43, 0xff,    \
  0x9a, 0xdc, 0x72, 0x50, 0x02, 0xe3, 0xda, 0x94, 0x31, 0x46, 0x2b, 0x68,    \
  0xa4, 0xe4, 0x45, 0x41, 0xd9, 0xfb, 0x00, 0xe6, 0x39                       \
}
/* END FILE */

/* This is taken from tests/data_files/test-ca.key */
/* BEGIN FILE string macro TEST_CA_KEY_RSA_PEM tests/data_files/test-ca.key */
#define TEST_CA_KEY_RSA_PEM                                                \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "Proc-Type: 4,ENCRYPTED\r\n"                                           \
    "DEK-Info: DES-EDE3-CBC,A8A95B05D5B7206B\r\n"                          \
    "\r\n"                                                                 \
    "9Qd9GeArejl1GDVh2lLV1bHt0cPtfbh5h/5zVpAVaFpqtSPMrElp50Rntn9et+JA\r\n" \
    "7VOyboR+Iy2t/HU4WvA687k3Bppe9GwKHjHhtl//8xFKwZr3Xb5yO5JUP8AUctQq\r\n" \
    "Nb8CLlZyuUC+52REAAthdWgsX+7dJO4yabzUcQ22Tp9JSD0hiL43BlkWYUNK3dAo\r\n" \
    "PZlmiptjnzVTjg1MxsBSydZinWOLBV8/JQgxSPo2yD4uEfig28qbvQ2wNIn0pnAb\r\n" \
    "GxnSAOazkongEGfvcjIIs+LZN9gXFhxcOh6kc4Q/c99B7QWETwLLkYgZ+z1a9VY9\r\n" \
    "gEU7CwCxYCD+h9hY6FPmsK0/lC4O7aeRKpYq00rPPxs6i7phiexg6ax6yTMmArQq\r\n" \
    "QmK3TAsJm8V/J5AWpLEV6jAFgRGymGGHnof0DXzVWZidrcZJWTNuGEX90nB3ee2w\r\n" \
    "PXJEFWKoD3K3aFcSLdHYr3mLGxP7H9ThQai9VsycxZKS5kwvBKQ//YMrmFfwPk8x\r\n" \
    "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU\r\n" \
    "WJZAwlsQn+QzCDwpri7+sV1mS3gBE6UY7aQmnmiiaC2V3Hbphxct/en5QsfDOt1X\r\n" \
    "JczSfpRWLlbPznZg8OQh/VgCMA58N5DjOzTIK7sJJ5r+94ZBTCpgAMbF588f0NTR\r\n" \
    "KCe4yrxGJR7X02M4nvD4IwOlpsQ8xQxZtOSgXv4LkxvdU9XJJKWZ/XNKJeWztxSe\r\n" \
    "Z1vdTc2YfsDBA2SEv33vxHx2g1vqtw8SjDRT2RaQSS0QuSaMJimdOX6mTOCBKk1J\r\n" \
    "9Q5mXTrER+/LnK0jEmXsBXWA5bqqVZIyahXSx4VYZ7l7w/PHiUDtDgyRhMMKi4n2\r\n" \
    "iQvQcWSQTjrpnlJbca1/DkpRt3YwrvJwdqb8asZU2VrNETh5x0QVefDRLFiVpif/\r\n" \
    "tUaeAe/P1F8OkS7OIZDs1SUbv/sD2vMbhNkUoCms3/PvNtdnvgL4F0zhaDpKCmlT\r\n" \
    "P8vx49E7v5CyRNmED9zZg4o3wmMqrQO93PtTug3Eu9oVx1zPQM1NVMyBa2+f29DL\r\n" \
    "1nuTCeXdo9+ni45xx+jAI4DCwrRdhJ9uzZyC6962H37H6D+5naNvClFR1s6li1Gb\r\n" \
    "nqPoiy/OBsEx9CaDGcqQBp5Wme/3XW+6z1ISOx+igwNTVCT14mHdBMbya0eIKft5\r\n" \
    "X+GnwtgEMyCYyyWuUct8g4RzErcY9+yW9Om5Hzpx4zOuW4NPZgPDTgK+t2RSL/Yq\r\n" \
    "rE1njrgeGYcVeG3f+OftH4s6fPbq7t1A5ZgUscbLMBqr9tK+OqygR4EgKBPsH6Cz\r\n" \
    "L6zlv/2RV0qAHvVuDJcIDIgwY5rJtINEm32rhOeFNJwZS5MNIC1czXZx5//ugX7l\r\n" \
    "I4sy5nbVhwSjtAk8Xg5dZbdTZ6mIrb7xqH+fdakZor1khG7bC2uIwibD3cSl2XkR\r\n" \
    "wN48lslbHnqqagr6Xm1nNOSVl8C/6kbJEsMpLhAezfRtGwvOucoaE+WbeUNolGde\r\n" \
    "P/eQiddSf0brnpiLJRh7qZrl9XuqYdpUqnoEdMAfotDOID8OtV7gt8a48ad8VPW2\r\n" \
    "-----END RSA PRIVATE KEY-----\r\n"
/* END FILE */

#define TEST_CA_PWD_RSA_PEM "PolarSSLTest"

/* This was generated from test-ca.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CA_KEY_RSA_DER tests/data_files/test-ca.key.der */
#define TEST_CA_KEY_RSA_DER {                                                \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc0, 0xdf, 0x37, 0xfc, 0x17, 0xbb, 0xe0, 0x96, 0x9d, 0x3f, 0x86, 0xde,  \
    0x96, 0x32, 0x7d, 0x44, 0xa5, 0x16, 0xa0, 0xcd, 0x21, 0xf1, 0x99, 0xd4,  \
    0xec, 0xea, 0xcb, 0x7c, 0x18, 0x58, 0x08, 0x94, 0xa5, 0xec, 0x9b, 0xc5,  \
    0x8b, 0xdf, 0x1a, 0x1e, 0x99, 0x38, 0x99, 0x87, 0x1e, 0x7b, 0xc0, 0x8d,  \
    0x39, 0xdf, 0x38, 0x5d, 0x70, 0x78, 0x07, 0xd3, 0x9e, 0xd9, 0x93, 0xe8,  \
    0xb9, 0x72, 0x51, 0xc5, 0xce, 0xa3, 0x30, 0x52, 0xa9, 0xf2, 0xe7, 0x40,  \
    0x70, 0x14, 0xcb, 0x44, 0xa2, 0x72, 0x0b, 0xc2, 0xe5, 0x40, 0xf9, 0x3e,  \
    0xe5, 0xa6, 0x0e, 0xb3, 0xf9, 0xec, 0x4a, 0x63, 0xc0, 0xb8, 0x29, 0x00,  \
    0x74, 0x9c, 0x57, 0x3b, 0xa8, 0xa5, 0x04, 0x90, 0x71, 0xf1, 0xbd, 0x83,  \
    0xd9, 0x3f, 0xd6, 0xa5, 0xe2, 0x3c, 0x2a, 0x8f, 0xef, 0x27, 0x60, 0xc3,  \
    0xc6, 0x9f, 0xcb, 0xba, 0xec, 0x60, 0x7d, 0xb7, 0xe6, 0x84, 0x32, 0xbe,  \
    0x4f, 0xfb, 0x58, 0x26, 0x22, 0x03, 0x5b, 0xd4, 0xb4, 0xd5, 0xfb, 0xf5,  \
    0xe3, 0x96, 0x2e, 0x70, 0xc0, 0xe4, 0x2e, 0xbd, 0xfc, 0x2e, 0xee, 0xe2,  \
    0x41, 0x55, 0xc0, 0x34, 0x2e, 0x7d, 0x24, 0x72, 0x69, 0xcb, 0x47, 0xb1,  \
    0x14, 0x40, 0x83, 0x7d, 0x67, 0xf4, 0x86, 0xf6, 0x31, 0xab, 0xf1, 0x79,  \
    0xa4, 0xb2, 0xb5, 0x2e, 0x12, 0xf9, 0x84, 0x17, 0xf0, 0x62, 0x6f, 0x27,  \
    0x3e, 0x13, 0x58, 0xb1, 0x54, 0x0d, 0x21, 0x9a, 0x73, 0x37, 0xa1, 0x30,  \
    0xcf, 0x6f, 0x92, 0xdc, 0xf6, 0xe9, 0xfc, 0xac, 0xdb, 0x2e, 0x28, 0xd1,  \
    0x7e, 0x02, 0x4b, 0x23, 0xa0, 0x15, 0xf2, 0x38, 0x65, 0x64, 0x09, 0xea,  \
    0x0c, 0x6e, 0x8e, 0x1b, 0x17, 0xa0, 0x71, 0xc8, 0xb3, 0x9b, 0xc9, 0xab,  \
    0xe9, 0xc3, 0xf2, 0xcf, 0x87, 0x96, 0x8f, 0x80, 0x02, 0x32, 0x9e, 0x99,  \
    0x58, 0x6f, 0xa2, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x00, 0x3f, 0xf7, 0x07, 0xd3, 0x34, 0x6f, 0xdb, 0xc9, 0x37, 0xb7, 0x84,  \
    0xdc, 0x37, 0x45, 0xe1, 0x63, 0xad, 0xb8, 0xb6, 0x75, 0xb1, 0xc7, 0x35,  \
    0xb4, 0x77, 0x2a, 0x5b, 0x77, 0xf9, 0x7e, 0xe0, 0xc1, 0xa3, 0xd1, 0xb7,  \
    0xcb, 0xa9, 0x5a, 0xc1, 0x87, 0xda, 0x5a, 0xfa, 0x17, 0xe4, 0xd5, 0x38,  \
    0x03, 0xde, 0x68, 0x98, 0x81, 0xec, 0xb5, 0xf2, 0x2a, 0x8d, 0xe9, 0x2c,  \
    0xf3, 0xa6, 0xe5, 0x32, 0x17, 0x7f, 0x33, 0x81, 0xe8, 0x38, 0x72, 0xd5,  \
    0x9c, 0xfa, 0x4e, 0xfb, 0x26, 0xf5, 0x15, 0x0b, 0xaf, 0x84, 0x66, 0xab,  \
    0x02, 0xe0, 0x18, 0xd5, 0x91, 0x7c, 0xd6, 0x8f, 0xc9, 0x4b, 0x76, 0x08,  \
    0x2b, 0x1d, 0x81, 0x68, 0x30, 0xe1, 0xfa, 0x70, 0x6c, 0x13, 0x4e, 0x10,  \
    0x03, 0x35, 0x3e, 0xc5, 0xca, 0x58, 0x20, 0x8a, 0x21, 0x18, 0x38, 0xa0,  \
    0x0f, 0xed, 0xc4, 0xbb, 0x45, 0x6f, 0xf5, 0x84, 0x5b, 0xb0, 0xcf, 0x4e,  \
    0x9d, 0x58, 0x13, 0x6b, 0x35, 0x35, 0x69, 0xa1, 0xd2, 0xc4, 0xf2, 0xc1,  \
    0x48, 0x04, 0x20, 0x51, 0xb9, 0x6b, 0xa4, 0x5d, 0xa5, 0x4b, 0x84, 0x88,  \
    0x43, 0x48, 0x99, 0x2c, 0xbb, 0xa4, 0x97, 0xd6, 0xd6, 0x18, 0xf6, 0xec,  \
    0x5c, 0xd1, 0x31, 0x49, 0xc9, 0xf2, 0x8f, 0x0b, 0x4d, 0xef, 0x09, 0x02,  \
    0xfe, 0x7d, 0xfd, 0xbb, 0xaf, 0x2b, 0x83, 0x94, 0x22, 0xc4, 0xa7, 0x3e,  \
    0x66, 0xf5, 0xe0, 0x57, 0xdc, 0xf2, 0xed, 0x2c, 0x3e, 0x81, 0x74, 0x76,  \
    0x1e, 0x96, 0x6f, 0x74, 0x1e, 0x32, 0x0e, 0x14, 0x31, 0xd0, 0x74, 0xf0,  \
    0xf4, 0x07, 0xbd, 0xc3, 0xd1, 0x22, 0xc2, 0xa8, 0x95, 0x92, 0x06, 0x7f,  \
    0x43, 0x02, 0x91, 0xbc, 0xdd, 0x23, 0x01, 0x89, 0x94, 0x20, 0x44, 0x64,  \
    0xf5, 0x1d, 0x67, 0xd2, 0x8f, 0xe8, 0x69, 0xa5, 0x29, 0x25, 0xe6, 0x50,  \
    0x9c, 0xe3, 0xe9, 0xcb, 0x75, 0x02, 0x81, 0x81, 0x00, 0xe2, 0x29, 0x3e,  \
    0xaa, 0x6b, 0xd5, 0x59, 0x1e, 0x9c, 0xe6, 0x47, 0xd5, 0xb6, 0xd7, 0xe3,  \
    0xf1, 0x8e, 0x9e, 0xe9, 0x83, 0x5f, 0x10, 0x9f, 0x63, 0xec, 0x04, 0x44,  \
    0xcc, 0x3f, 0xf8, 0xd9, 0x3a, 0x17, 0xe0, 0x4f, 0xfe, 0xd8, 0x4d, 0xcd,  \
    0x46, 0x54, 0x74, 0xbf, 0x0a, 0xc4, 0x67, 0x9c, 0xa7, 0xd8, 0x89, 0x65,  \
    0x4c, 0xfd, 0x58, 0x2a, 0x47, 0x0f, 0xf4, 0x37, 0xb6, 0x55, 0xb0, 0x1d,  \
    0xed, 0xa7, 0x39, 0xfc, 0x4f, 0xa3, 0xc4, 0x75, 0x3a, 0xa3, 0x98, 0xa7,  \
    0x45, 0xf5, 0x66, 0xcb, 0x7c, 0x65, 0xfb, 0x80, 0x23, 0xe6, 0xff, 0xfd,  \
    0x99, 0x1f, 0x8e, 0x6b, 0xff, 0x5e, 0x93, 0x66, 0xdf, 0x6c, 0x6f, 0xc3,  \
    0xf6, 0x38, 0x2e, 0xff, 0x69, 0xb5, 0xac, 0xae, 0xbb, 0xc6, 0x71, 0x16,  \
    0x6b, 0xd0, 0xf8, 0x22, 0xd9, 0xf8, 0xa2, 0x72, 0x20, 0xd2, 0xe2, 0x3a,  \
    0x70, 0x4b, 0xde, 0xab, 0x2f, 0x02, 0x81, 0x81, 0x00, 0xda, 0x51, 0x9b,  \
    0xb8, 0xb2, 0x2a, 0x14, 0x75, 0x58, 0x40, 0x8d, 0x27, 0x70, 0xfa, 0x31,  \
    0x48, 0xb0, 0x20, 0x21, 0x34, 0xfa, 0x4c, 0x57, 0xa8, 0x11, 0x88, 0xf3,  \
    0xa7, 0xae, 0x21, 0xe9, 0xb6, 0x2b, 0xd1, 0xcd, 0xa7, 0xf8, 0xd8, 0x0c,  \
    0x8a, 0x76, 0x22, 0x35, 0x44, 0xce, 0x3f, 0x25, 0x29, 0x83, 0x7d, 0x79,  \
    0xa7, 0x31, 0xd6, 0xec, 0xb2, 0xbf, 0xda, 0x34, 0xb6, 0xf6, 0xb2, 0x3b,  \
    0xf3, 0x78, 0x5a, 0x04, 0x83, 0x33, 0x3e, 0xa2, 0xe2, 0x81, 0x82, 0x13,  \
    0xd4, 0x35, 0x17, 0x63, 0x9b, 0x9e, 0xc4, 0x8d, 0x91, 0x4c, 0x03, 0x77,  \
    0xc7, 0x71, 0x5b, 0xee, 0x83, 0x6d, 0xd5, 0x78, 0x88, 0xf6, 0x2c, 0x79,  \
    0xc2, 0x4a, 0xb4, 0x79, 0x90, 0x70, 0xbf, 0xdf, 0x34, 0x56, 0x96, 0x71,  \
    0xe3, 0x0e, 0x68, 0x91, 0xbc, 0xea, 0xcb, 0x33, 0xc0, 0xbe, 0x45, 0xd7,  \
    0xfc, 0x30, 0xfd, 0x01, 0x3b, 0x02, 0x81, 0x81, 0x00, 0xd2, 0x9f, 0x2a,  \
    0xb7, 0x38, 0x19, 0xc7, 0x17, 0x95, 0x73, 0x78, 0xae, 0xf5, 0xcb, 0x75,  \
    0x83, 0x7f, 0x19, 0x4b, 0xcb, 0x86, 0xfb, 0x4a, 0x15, 0x9a, 0xb6, 0x17,  \
    0x04, 0x49, 0x07, 0x8d, 0xf6, 0x66, 0x4a, 0x06, 0xf6, 0x05, 0xa7, 0xdf,  \
    0x66, 0x82, 0x3c, 0xff, 0xb6, 0x1d, 0x57, 0x89, 0x33, 0x5f, 0x9c, 0x05,  \
    0x75, 0x7f, 0xf3, 0x5d, 0xdc, 0x34, 0x65, 0x72, 0x85, 0x22, 0xa4, 0x14,  \
    0x1b, 0x41, 0xc3, 0xe4, 0xd0, 0x9e, 0x69, 0xd5, 0xeb, 0x38, 0x74, 0x70,  \
    0x43, 0xdc, 0xd9, 0x50, 0xe4, 0x97, 0x6d, 0x73, 0xd6, 0xfb, 0xc8, 0xa7,  \
    0xfa, 0xb4, 0xc2, 0xc4, 0x9d, 0x5d, 0x0c, 0xd5, 0x9f, 0x79, 0xb3, 0x54,  \
    0xc2, 0xb7, 0x6c, 0x3d, 0x7d, 0xcb, 0x2d, 0xf8, 0xc4, 0xf3, 0x78, 0x5a,  \
    0x33, 0x2a, 0xb8, 0x0c, 0x6d, 0x06, 0xfa, 0xf2, 0x62, 0xd3, 0x42, 0xd0,  \
    0xbd, 0xc8, 0x4a, 0xa5, 0x0d, 0x02, 0x81, 0x81, 0x00, 0xd4, 0xa9, 0x90,  \
    0x15, 0xde, 0xbf, 0x2c, 0xc4, 0x8d, 0x9d, 0xfb, 0xa1, 0xc2, 0xe4, 0x83,  \
    0xe3, 0x79, 0x65, 0x22, 0xd3, 0xb7, 0x49, 0x6c, 0x4d, 0x94, 0x1f, 0x22,  \
    0xb1, 0x60, 0xe7, 0x3a, 0x00, 0xb1, 0x38, 0xa2, 0xab, 0x0f, 0xb4, 0x6c,  \
    0xaa, 0xe7, 0x9e, 0x34, 0xe3, 0x7c, 0x40, 0x78, 0x53, 0xb2, 0xf9, 0x23,  \
    0xea, 0xa0, 0x9a, 0xea, 0x60, 0xc8, 0x8f, 0xa6, 0xaf, 0xdf, 0x29, 0x09,  \
    0x4b, 0x06, 0x1e, 0x31, 0xad, 0x17, 0xda, 0xd8, 0xd1, 0xe9, 0x33, 0xab,  \
    0x5b, 0x18, 0x08, 0x5b, 0x87, 0xf8, 0xa5, 0x1f, 0xfd, 0xbb, 0xdc, 0xd8,  \
    0xed, 0x97, 0x57, 0xe4, 0xc3, 0x73, 0xd6, 0xf0, 0x9e, 0x01, 0xa6, 0x9b,  \
    0x48, 0x8e, 0x7a, 0xb4, 0xbb, 0xe5, 0x88, 0x91, 0xc5, 0x2a, 0xdf, 0x4b,  \
    0xba, 0xd0, 0x8b, 0x3e, 0x03, 0x97, 0x77, 0x2f, 0x47, 0x7e, 0x51, 0x0c,  \
    0xae, 0x65, 0x8d, 0xde, 0x87, 0x02, 0x81, 0x80, 0x20, 0x24, 0x0f, 0xd2,  \
    0xaf, 0xc2, 0x28, 0x3b, 0x97, 0x20, 0xb2, 0x92, 0x49, 0xeb, 0x09, 0x68,  \
    0x40, 0xb2, 0xbe, 0xd1, 0xc3, 0x83, 0x94, 0x34, 0x38, 0xd6, 0xc9, 0xec,  \
    0x34, 0x09, 0xf9, 0x41, 0x6d, 0x5c, 0x42, 0x94, 0xf7, 0x04, 0xfc, 0x32,  \
    0x39, 0x69, 0xbc, 0x1c, 0xfb, 0x3e, 0x61, 0x98, 0xc0, 0x80, 0xd8, 0x36,  \
    0x47, 0xc3, 0x6d, 0xc2, 0x2e, 0xe7, 0x81, 0x2a, 0x17, 0x34, 0x64, 0x30,  \
    0x4e, 0x96, 0xbb, 0x26, 0x16, 0xb9, 0x41, 0x36, 0xfe, 0x8a, 0xd6, 0x53,  \
    0x7c, 0xaa, 0xec, 0x39, 0x42, 0x50, 0xef, 0xe3, 0xb3, 0x01, 0x28, 0x32,  \
    0xca, 0x6d, 0xf5, 0x9a, 0x1e, 0x9f, 0x37, 0xbe, 0xfe, 0x38, 0x20, 0x22,  \
    0x91, 0x8c, 0xcd, 0x95, 0x02, 0xf2, 0x4d, 0x6f, 0x1a, 0xb4, 0x43, 0xf0,  \
    0x19, 0xdf, 0x65, 0xc0, 0x92, 0xe7, 0x9d, 0x2f, 0x09, 0xe7, 0xec, 0x69,  \
    0xa8, 0xc2, 0x8f, 0x0d                                                   \
}
/* END FILE */

/*
 * Test server Certificates
 *
 * Test server certificates are defined for each choice
 * of the following parameters:
 * - PEM or DER encoding
 * - SHA-1 or SHA-256 hash
 * - RSA or EC key
 *
 * Things to add:
 * - multiple EC curve types
 */

/* This is taken from tests/data_files/server5.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_EC_PEM tests/data_files/server5.crt */
#define TEST_SRV_CRT_EC_PEM                                                \
  "-----BEGIN CERTIFICATE-----\r\n"	\
  "MIICNDCCAZWgAwIBAgIBATAMBggqhkjOPQQDAgUAMDYxGTAXBgNVBAMMEFJvb3Qg\r\n"	\
  "Q2VydGlmaWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswHhcNMjIwMTAx\r\n"	\
  "MDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA4MRswGQYDVQQDDBJFbnRpdHkgQ2VydGlm\r\n"	\
  "aWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswgZswEAYHKoZIzj0CAQYF\r\n"	\
  "K4EEACMDgYYABAAUINv1t0sceo02BkY9lxGfVsilbQiEA9eoseMLEnp4qJukF8Yb\r\n"	\
  "0uJ4A/Ioj6if+OQI1Yhe+TMeLwzbPDMDNEgcywE7M6oka/mmTYv84KogodwPOHJx\r\n"	\
  "KWKPqlONIl/wpHiokNkKc6zY1nx5ts1zDbmRcixjrKlolcjFOSWlAxfTC9+HxqNN\r\n"	\
  "MEswCQYDVR0TBAIwADAdBgNVHQ4EFgQUQqsX/4zNZGGX8IRPbla2Ak1bLMkwHwYD\r\n"	\
  "VR0jBBgwFoAUzObtm+F3RSTZyX8hga4LQA21C8IwDAYIKoZIzj0EAwIFAAOBigAw\r\n"	\
  "gYYCQSUTi+jGRueKlXvE1aG+fhQmO9/dP8trHUUud0o8SKZj7wK6h0HFmHVBBFen\r\n"	\
  "Mlgx4wgK0kBw+9bO+RnsNPSGHmUVAkF76RKU+syXd1ZBn1fO5Dv1t3RCRI5zzVwJ\r\n"	\
  "Ln6zYQrZt6FgxDg6ALBxgHvNdRo/OC8MVmwhalVpNVPehGyvsWY10g==\r\n"	\
  "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/server5.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_CRT_EC_DER tests/data_files/server5.crt.der */
#define TEST_SRV_CRT_EC_DER {                                                \
    0x30, 0x82, 0x02, 0x1f, 0x30, 0x82, 0x01, 0xa5, 0xa0, 0x03, 0x02, 0x01,  \
    0x02, 0x02, 0x01, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,  \
    0x3d, 0x04, 0x03, 0x02, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,  \
    0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,  \
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,  \
    0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,  \
    0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65,  \
    0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,  \
    0x31, 0x33, 0x30, 0x39, 0x32, 0x34, 0x31, 0x35, 0x35, 0x32, 0x30, 0x34,  \
    0x5a, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x39, 0x32, 0x32, 0x31, 0x35, 0x35,  \
    0x32, 0x30, 0x34, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,  \
    0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,  \
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,  \
    0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,  \
    0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59,  \
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,  \
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,  \
    0x04, 0x37, 0xcc, 0x56, 0xd9, 0x76, 0x09, 0x1e, 0x5a, 0x72, 0x3e, 0xc7,  \
    0x59, 0x2d, 0xff, 0x20, 0x6e, 0xee, 0x7c, 0xf9, 0x06, 0x91, 0x74, 0xd0,  \
    0xad, 0x14, 0xb5, 0xf7, 0x68, 0x22, 0x59, 0x62, 0x92, 0x4e, 0xe5, 0x00,  \
    0xd8, 0x23, 0x11, 0xff, 0xea, 0x2f, 0xd2, 0x34, 0x5d, 0x5d, 0x16, 0xbd,  \
    0x8a, 0x88, 0xc2, 0x6b, 0x77, 0x0d, 0x55, 0xcd, 0x8a, 0x2a, 0x0e, 0xfa,  \
    0x01, 0xc8, 0xb4, 0xed, 0xff, 0xa3, 0x81, 0x9d, 0x30, 0x81, 0x9a, 0x30,  \
    0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d,  \
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x50, 0x61, 0xa5,  \
    0x8f, 0xd4, 0x07, 0xd9, 0xd7, 0x82, 0x01, 0x0c, 0xe5, 0x65, 0x7f, 0x8c,  \
    0x63, 0x46, 0xa7, 0x13, 0xbe, 0x30, 0x6e, 0x06, 0x03, 0x55, 0x1d, 0x23,  \
    0x04, 0x67, 0x30, 0x65, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24, 0x49, 0x01,  \
    0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb, 0xfb,  \
    0x36, 0x7c, 0xa1, 0x42, 0xa4, 0x40, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09,  \
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,  \
    0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61,  \
    0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,  \
    0x03, 0x13, 0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, 0x20,  \
    0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x82, 0x09,  \
    0x00, 0xc1, 0x43, 0xe2, 0x7e, 0x62, 0x43, 0xcc, 0xe8, 0x30, 0x0a, 0x06,  \
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x68, 0x00,  \
    0x30, 0x65, 0x02, 0x31, 0x00, 0x9a, 0x2c, 0x5c, 0xd7, 0xa6, 0xdb, 0xa2,  \
    0xe5, 0x64, 0x0d, 0xf0, 0xb9, 0x4e, 0xdd, 0xd7, 0x61, 0xd6, 0x13, 0x31,  \
    0xc7, 0xab, 0x73, 0x80, 0xbb, 0xd3, 0xd3, 0x73, 0x13, 0x54, 0xad, 0x92,  \
    0x0b, 0x5d, 0xab, 0xd0, 0xbc, 0xf7, 0xae, 0x2f, 0xe6, 0xa1, 0x21, 0x29,  \
    0x35, 0x95, 0xaa, 0x3e, 0x39, 0x02, 0x30, 0x21, 0x36, 0x7f, 0x9d, 0xc6,  \
    0x5d, 0xc6, 0x0b, 0xab, 0x27, 0xf2, 0x25, 0x1d, 0x3b, 0xf1, 0xcf, 0xf1,  \
    0x35, 0x25, 0x14, 0xe7, 0xe5, 0xf1, 0x97, 0xb5, 0x59, 0xe3, 0x5e, 0x15,  \
    0x7c, 0x66, 0xb9, 0x90, 0x7b, 0xc7, 0x01, 0x10, 0x4f, 0x73, 0xc6, 0x00,  \
    0x21, 0x52, 0x2a, 0x0e, 0xf1, 0xc7, 0xd5                                 \
}
/* END FILE */

/* This is taken from tests/data_files/server5.key. */
/* BEGIN FILE string macro TEST_SRV_KEY_EC_PEM tests/data_files/server5.key */
#define TEST_SRV_KEY_EC_PEM                                                \
  "-----BEGIN EC PRIVATE KEY-----\r\n"	\
  "MIHcAgEBBEIARL2NqmjtQSNwf0wvYtQveTsnWzTORKmnYbbkvbSXBNtWuvrXHV0F\r\n"	\
  "bupM+y11nJA/9F9yUSmmn+Tqr7bisaiLw3ygBwYFK4EEACOhgYkDgYYABAAUINv1\r\n"	\
  "t0sceo02BkY9lxGfVsilbQiEA9eoseMLEnp4qJukF8Yb0uJ4A/Ioj6if+OQI1Yhe\r\n"	\
  "+TMeLwzbPDMDNEgcywE7M6oka/mmTYv84KogodwPOHJxKWKPqlONIl/wpHiokNkK\r\n"	\
  "c6zY1nx5ts1zDbmRcixjrKlolcjFOSWlAxfTC9+Hxg==\r\n"	\
  "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/server5.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_KEY_EC_DER tests/data_files/server5.key.der */
#define TEST_SRV_KEY_EC_DER {                                                \
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xf1, 0x2a, 0x13, 0x20, 0x76,  \
    0x02, 0x70, 0xa8, 0x3c, 0xbf, 0xfd, 0x53, 0xf6, 0x03, 0x1e, 0xf7, 0x6a,  \
    0x5d, 0x86, 0xc8, 0xa2, 0x04, 0xf2, 0xc3, 0x0c, 0xa9, 0xeb, 0xf5, 0x1f,  \
    0x0f, 0x0e, 0xa7, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  \
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x37, 0xcc, 0x56,  \
    0xd9, 0x76, 0x09, 0x1e, 0x5a, 0x72, 0x3e, 0xc7, 0x59, 0x2d, 0xff, 0x20,  \
    0x6e, 0xee, 0x7c, 0xf9, 0x06, 0x91, 0x74, 0xd0, 0xad, 0x14, 0xb5, 0xf7,  \
    0x68, 0x22, 0x59, 0x62, 0x92, 0x4e, 0xe5, 0x00, 0xd8, 0x23, 0x11, 0xff,  \
    0xea, 0x2f, 0xd2, 0x34, 0x5d, 0x5d, 0x16, 0xbd, 0x8a, 0x88, 0xc2, 0x6b,  \
    0x77, 0x0d, 0x55, 0xcd, 0x8a, 0x2a, 0x0e, 0xfa, 0x01, 0xc8, 0xb4, 0xed,  \
    0xff                                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/server2-sha256.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_RSA_SHA256_PEM tests/data_files/server2-sha256.crt */
#define TEST_SRV_CRT_RSA_SHA256_PEM                                        \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDNzCCAh+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n" \
    "AQEBBQADggEPADCCAQoCggEBAMFNo93nzR3RBNdJcriZrA545Do8Ss86ExbQWuTN\r\n" \
    "owCIp+4ea5anUrSQ7y1yej4kmvy2NKwk9XfgJmSMnLAofaHa6ozmyRyWvP7BBFKz\r\n" \
    "NtSj+uGxdtiQwWG0ZlI2oiZTqqt0Xgd9GYLbKtgfoNkNHC1JZvdbJXNG6AuKT2kM\r\n" \
    "tQCQ4dqCEGZ9rlQri2V5kaHiYcPNQEkI7mgM8YuG0ka/0LiqEQMef1aoGh5EGA8P\r\n" \
    "hYvai0Re4hjGYi/HZo36Xdh98yeJKQHFkA4/J/EwyEoO79bex8cna8cFPXrEAjya\r\n" \
    "HT4P6DSYW8tzS1KW2BGiLICIaTla0w+w3lkvEcf36hIBMJcCAwEAAaNNMEswCQYD\r\n" \
    "VR0TBAIwADAdBgNVHQ4EFgQUpQXoZLjc32APUBJNYKhkr02LQ5MwHwYDVR0jBBgw\r\n" \
    "FoAUtFrkpbPe0lL2udWmlQ/rPrzH/f8wDQYJKoZIhvcNAQELBQADggEBAC465FJh\r\n" \
    "Pqel7zJngHIHJrqj/wVAxGAFOTF396XKATGAp+HRCqJ81Ry60CNK1jDzk8dv6M6U\r\n" \
    "HoS7RIFiM/9rXQCbJfiPD5xMTejZp5n5UYHAmxsxDaazfA5FuBhkfokKK6jD4Eq9\r\n" \
    "1C94xGKb6X4/VkaPF7cqoBBw/bHxawXc0UEPjqayiBpCYU/rJoVZgLqFVP7Px3sv\r\n" \
    "a1nOrNx8rPPI1hJ+ZOg8maiPTxHZnBVLakSSLQy/sWeWyazO1RnrbxjrbgQtYKz0\r\n" \
    "e3nwGpu1w13vfckFmUSBhHXH7AAS/HpKC4IH7G2GAk3+n8iSSN71sZzpxonQwVbo\r\n" \
    "pMZqLmbBm/7WPLc=\r\n"                                                 \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/server2-sha256.crt.der. */
/* BEGIN FILE binary macro TEST_SRV_CRT_RSA_SHA256_DER tests/data_files/server2-sha256.crt.der */
#define TEST_SRV_CRT_RSA_SHA256_DER {                                        \
  0x30, 0x82, 0x03, 0x37, 0x30, 0x82, 0x02, 0x1f, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82,    \
  0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,    \
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,    \
  0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc1, 0x4d, 0xa3, 0xdd, 0xe7,    \
  0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72, 0xb8, 0x99, 0xac, 0x0e, 0x78,    \
  0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13, 0x16, 0xd0, 0x5a, 0xe4, 0xcd,    \
  0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b, 0x96, 0xa7, 0x52, 0xb4, 0x90,    \
  0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a, 0xfc, 0xb6, 0x34, 0xac, 0x24,    \
  0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c, 0xb0, 0x28, 0x7d, 0xa1, 0xda,    \
  0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc, 0xfe, 0xc1, 0x04, 0x52, 0xb3,    \
  0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76, 0xd8, 0x90, 0xc1, 0x61, 0xb4,    \
  0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa, 0xab, 0x74, 0x5e, 0x07, 0x7d,    \
  0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0, 0xd9, 0x0d, 0x1c, 0x2d, 0x49,    \
  0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8, 0x0b, 0x8a, 0x4f, 0x69, 0x0c,    \
  0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10, 0x66, 0x7d, 0xae, 0x54, 0x2b,    \
  0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61, 0xc3, 0xcd, 0x40, 0x49, 0x08,    \
  0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2, 0x46, 0xbf, 0xd0, 0xb8, 0xaa,    \
  0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a, 0x1e, 0x44, 0x18, 0x0f, 0x0f,    \
  0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2, 0x18, 0xc6, 0x62, 0x2f, 0xc7,    \
  0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3, 0x27, 0x89, 0x29, 0x01, 0xc5,    \
  0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8, 0x4a, 0x0e, 0xef, 0xd6, 0xde,    \
  0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d, 0x7a, 0xc4, 0x02, 0x3c, 0x9a,    \
  0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b, 0xcb, 0x73, 0x4b, 0x52, 0x96,    \
  0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69, 0x39, 0x5a, 0xd3, 0x0f, 0xb0,    \
  0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea, 0x12, 0x01, 0x30, 0x97, 0x02,    \
  0x03, 0x01, 0x00, 0x01, 0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,    \
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa5, 0x05, 0xe8, 0x64, 0xb8, 0xdc,    \
  0xdf, 0x60, 0x0f, 0x50, 0x12, 0x4d, 0x60, 0xa8, 0x64, 0xaf, 0x4d, 0x8b,    \
  0x43, 0x93, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,    \
  0x16, 0x80, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6,    \
  0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30,    \
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,    \
  0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x2e, 0x3a, 0xe4, 0x52, 0x61,    \
  0x3e, 0xa7, 0xa5, 0xef, 0x32, 0x67, 0x80, 0x72, 0x07, 0x26, 0xba, 0xa3,    \
  0xff, 0x05, 0x40, 0xc4, 0x60, 0x05, 0x39, 0x31, 0x77, 0xf7, 0xa5, 0xca,    \
  0x01, 0x31, 0x80, 0xa7, 0xe1, 0xd1, 0x0a, 0xa2, 0x7c, 0xd5, 0x1c, 0xba,    \
  0xd0, 0x23, 0x4a, 0xd6, 0x30, 0xf3, 0x93, 0xc7, 0x6f, 0xe8, 0xce, 0x94,    \
  0x1e, 0x84, 0xbb, 0x44, 0x81, 0x62, 0x33, 0xff, 0x6b, 0x5d, 0x00, 0x9b,    \
  0x25, 0xf8, 0x8f, 0x0f, 0x9c, 0x4c, 0x4d, 0xe8, 0xd9, 0xa7, 0x99, 0xf9,    \
  0x51, 0x81, 0xc0, 0x9b, 0x1b, 0x31, 0x0d, 0xa6, 0xb3, 0x7c, 0x0e, 0x45,    \
  0xb8, 0x18, 0x64, 0x7e, 0x89, 0x0a, 0x2b, 0xa8, 0xc3, 0xe0, 0x4a, 0xbd,    \
  0xd4, 0x2f, 0x78, 0xc4, 0x62, 0x9b, 0xe9, 0x7e, 0x3f, 0x56, 0x46, 0x8f,    \
  0x17, 0xb7, 0x2a, 0xa0, 0x10, 0x70, 0xfd, 0xb1, 0xf1, 0x6b, 0x05, 0xdc,    \
  0xd1, 0x41, 0x0f, 0x8e, 0xa6, 0xb2, 0x88, 0x1a, 0x42, 0x61, 0x4f, 0xeb,    \
  0x26, 0x85, 0x59, 0x80, 0xba, 0x85, 0x54, 0xfe, 0xcf, 0xc7, 0x7b, 0x2f,    \
  0x6b, 0x59, 0xce, 0xac, 0xdc, 0x7c, 0xac, 0xf3, 0xc8, 0xd6, 0x12, 0x7e,    \
  0x64, 0xe8, 0x3c, 0x99, 0xa8, 0x8f, 0x4f, 0x11, 0xd9, 0x9c, 0x15, 0x4b,    \
  0x6a, 0x44, 0x92, 0x2d, 0x0c, 0xbf, 0xb1, 0x67, 0x96, 0xc9, 0xac, 0xce,    \
  0xd5, 0x19, 0xeb, 0x6f, 0x18, 0xeb, 0x6e, 0x04, 0x2d, 0x60, 0xac, 0xf4,    \
  0x7b, 0x79, 0xf0, 0x1a, 0x9b, 0xb5, 0xc3, 0x5d, 0xef, 0x7d, 0xc9, 0x05,    \
  0x99, 0x44, 0x81, 0x84, 0x75, 0xc7, 0xec, 0x00, 0x12, 0xfc, 0x7a, 0x4a,    \
  0x0b, 0x82, 0x07, 0xec, 0x6d, 0x86, 0x02, 0x4d, 0xfe, 0x9f, 0xc8, 0x92,    \
  0x48, 0xde, 0xf5, 0xb1, 0x9c, 0xe9, 0xc6, 0x89, 0xd0, 0xc1, 0x56, 0xe8,    \
  0xa4, 0xc6, 0x6a, 0x2e, 0x66, 0xc1, 0x9b, 0xfe, 0xd6, 0x3c, 0xb7           \
}
/* END FILE */

/* This is taken from tests/data_files/server2.crt. */
/* BEGIN FILE string macro TEST_SRV_CRT_RSA_SHA1_PEM tests/data_files/server2.crt */
#define TEST_SRV_CRT_RSA_SHA1_PEM                                          \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDNzCCAh+gAwIBAgIBAjANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN\r\n" \
    "AQEBBQADggEPADCCAQoCggEBAMFNo93nzR3RBNdJcriZrA545Do8Ss86ExbQWuTN\r\n" \
    "owCIp+4ea5anUrSQ7y1yej4kmvy2NKwk9XfgJmSMnLAofaHa6ozmyRyWvP7BBFKz\r\n" \
    "NtSj+uGxdtiQwWG0ZlI2oiZTqqt0Xgd9GYLbKtgfoNkNHC1JZvdbJXNG6AuKT2kM\r\n" \
    "tQCQ4dqCEGZ9rlQri2V5kaHiYcPNQEkI7mgM8YuG0ka/0LiqEQMef1aoGh5EGA8P\r\n" \
    "hYvai0Re4hjGYi/HZo36Xdh98yeJKQHFkA4/J/EwyEoO79bex8cna8cFPXrEAjya\r\n" \
    "HT4P6DSYW8tzS1KW2BGiLICIaTla0w+w3lkvEcf36hIBMJcCAwEAAaNNMEswCQYD\r\n" \
    "VR0TBAIwADAdBgNVHQ4EFgQUpQXoZLjc32APUBJNYKhkr02LQ5MwHwYDVR0jBBgw\r\n" \
    "FoAUtFrkpbPe0lL2udWmlQ/rPrzH/f8wDQYJKoZIhvcNAQEFBQADggEBAJklg3Q4\r\n" \
    "cB7v7BzsxM/vLyKccO6op0/gZzM4ghuLq2Y32kl0sM6kSNUUmduuq3u/+GmUZN2A\r\n" \
    "O/7c+Hw7hDFEIvZk98aBGjCLqn3DmgHIv8ToQ67nellQxx2Uj309PdgjNi/r9HOc\r\n" \
    "KNAYPbBcg6MJGWWj2TI6vNaceios/DhOYx5V0j5nfqSJ/pnU0g9Ign2LAhgYpGJE\r\n" \
    "iEM9wW7hEMkwmk0h/sqZsrJsGH5YsF/VThSq/JVO1e2mZH2vruyZKJVBq+8tDNYp\r\n" \
    "HkK6tSyVYQhzIt3StMJWKMl/o5k2AYz6tSC164+1oG+ML3LWg8XrGKa91H4UOKap\r\n" \
    "Awgk0+4m0T25cNs=\r\n"                                                 \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is taken from tests/data_files/server2.crt.der. */
/* BEGIN FILE binary macro TEST_SRV_CRT_RSA_SHA1_DER tests/data_files/server2.crt.der */
#define TEST_SRV_CRT_RSA_SHA1_DER {                                          \
  0x30, 0x82, 0x03, 0x37, 0x30, 0x82, 0x02, 0x1f, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82,    \
  0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,    \
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,    \
  0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc1, 0x4d, 0xa3, 0xdd, 0xe7,    \
  0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72, 0xb8, 0x99, 0xac, 0x0e, 0x78,    \
  0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13, 0x16, 0xd0, 0x5a, 0xe4, 0xcd,    \
  0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b, 0x96, 0xa7, 0x52, 0xb4, 0x90,    \
  0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a, 0xfc, 0xb6, 0x34, 0xac, 0x24,    \
  0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c, 0xb0, 0x28, 0x7d, 0xa1, 0xda,    \
  0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc, 0xfe, 0xc1, 0x04, 0x52, 0xb3,    \
  0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76, 0xd8, 0x90, 0xc1, 0x61, 0xb4,    \
  0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa, 0xab, 0x74, 0x5e, 0x07, 0x7d,    \
  0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0, 0xd9, 0x0d, 0x1c, 0x2d, 0x49,    \
  0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8, 0x0b, 0x8a, 0x4f, 0x69, 0x0c,    \
  0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10, 0x66, 0x7d, 0xae, 0x54, 0x2b,    \
  0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61, 0xc3, 0xcd, 0x40, 0x49, 0x08,    \
  0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2, 0x46, 0xbf, 0xd0, 0xb8, 0xaa,    \
  0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a, 0x1e, 0x44, 0x18, 0x0f, 0x0f,    \
  0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2, 0x18, 0xc6, 0x62, 0x2f, 0xc7,    \
  0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3, 0x27, 0x89, 0x29, 0x01, 0xc5,    \
  0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8, 0x4a, 0x0e, 0xef, 0xd6, 0xde,    \
  0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d, 0x7a, 0xc4, 0x02, 0x3c, 0x9a,    \
  0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b, 0xcb, 0x73, 0x4b, 0x52, 0x96,    \
  0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69, 0x39, 0x5a, 0xd3, 0x0f, 0xb0,    \
  0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea, 0x12, 0x01, 0x30, 0x97, 0x02,    \
  0x03, 0x01, 0x00, 0x01, 0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,    \
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa5, 0x05, 0xe8, 0x64, 0xb8, 0xdc,    \
  0xdf, 0x60, 0x0f, 0x50, 0x12, 0x4d, 0x60, 0xa8, 0x64, 0xaf, 0x4d, 0x8b,    \
  0x43, 0x93, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,    \
  0x16, 0x80, 0x14, 0xb4, 0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6,    \
  0xb9, 0xd5, 0xa6, 0x95, 0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30,    \
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,    \
  0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x99, 0x25, 0x83, 0x74, 0x38,    \
  0x70, 0x1e, 0xef, 0xec, 0x1c, 0xec, 0xc4, 0xcf, 0xef, 0x2f, 0x22, 0x9c,    \
  0x70, 0xee, 0xa8, 0xa7, 0x4f, 0xe0, 0x67, 0x33, 0x38, 0x82, 0x1b, 0x8b,    \
  0xab, 0x66, 0x37, 0xda, 0x49, 0x74, 0xb0, 0xce, 0xa4, 0x48, 0xd5, 0x14,    \
  0x99, 0xdb, 0xae, 0xab, 0x7b, 0xbf, 0xf8, 0x69, 0x94, 0x64, 0xdd, 0x80,    \
  0x3b, 0xfe, 0xdc, 0xf8, 0x7c, 0x3b, 0x84, 0x31, 0x44, 0x22, 0xf6, 0x64,    \
  0xf7, 0xc6, 0x81, 0x1a, 0x30, 0x8b, 0xaa, 0x7d, 0xc3, 0x9a, 0x01, 0xc8,    \
  0xbf, 0xc4, 0xe8, 0x43, 0xae, 0xe7, 0x7a, 0x59, 0x50, 0xc7, 0x1d, 0x94,    \
  0x8f, 0x7d, 0x3d, 0x3d, 0xd8, 0x23, 0x36, 0x2f, 0xeb, 0xf4, 0x73, 0x9c,    \
  0x28, 0xd0, 0x18, 0x3d, 0xb0, 0x5c, 0x83, 0xa3, 0x09, 0x19, 0x65, 0xa3,    \
  0xd9, 0x32, 0x3a, 0xbc, 0xd6, 0x9c, 0x7a, 0x2a, 0x2c, 0xfc, 0x38, 0x4e,    \
  0x63, 0x1e, 0x55, 0xd2, 0x3e, 0x67, 0x7e, 0xa4, 0x89, 0xfe, 0x99, 0xd4,    \
  0xd2, 0x0f, 0x48, 0x82, 0x7d, 0x8b, 0x02, 0x18, 0x18, 0xa4, 0x62, 0x44,    \
  0x88, 0x43, 0x3d, 0xc1, 0x6e, 0xe1, 0x10, 0xc9, 0x30, 0x9a, 0x4d, 0x21,    \
  0xfe, 0xca, 0x99, 0xb2, 0xb2, 0x6c, 0x18, 0x7e, 0x58, 0xb0, 0x5f, 0xd5,    \
  0x4e, 0x14, 0xaa, 0xfc, 0x95, 0x4e, 0xd5, 0xed, 0xa6, 0x64, 0x7d, 0xaf,    \
  0xae, 0xec, 0x99, 0x28, 0x95, 0x41, 0xab, 0xef, 0x2d, 0x0c, 0xd6, 0x29,    \
  0x1e, 0x42, 0xba, 0xb5, 0x2c, 0x95, 0x61, 0x08, 0x73, 0x22, 0xdd, 0xd2,    \
  0xb4, 0xc2, 0x56, 0x28, 0xc9, 0x7f, 0xa3, 0x99, 0x36, 0x01, 0x8c, 0xfa,    \
  0xb5, 0x20, 0xb5, 0xeb, 0x8f, 0xb5, 0xa0, 0x6f, 0x8c, 0x2f, 0x72, 0xd6,    \
  0x83, 0xc5, 0xeb, 0x18, 0xa6, 0xbd, 0xd4, 0x7e, 0x14, 0x38, 0xa6, 0xa9,    \
  0x03, 0x08, 0x24, 0xd3, 0xee, 0x26, 0xd1, 0x3d, 0xb9, 0x70, 0xdb           \
}
/* END FILE */

/* This is taken from tests/data_files/server2.key. */
/* BEGIN FILE string macro TEST_SRV_KEY_RSA_PEM tests/data_files/server2.key */
#define TEST_SRV_KEY_RSA_PEM                                               \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "MIIEpAIBAAKCAQEAwU2j3efNHdEE10lyuJmsDnjkOjxKzzoTFtBa5M2jAIin7h5r\r\n" \
    "lqdStJDvLXJ6PiSa/LY0rCT1d+AmZIycsCh9odrqjObJHJa8/sEEUrM21KP64bF2\r\n" \
    "2JDBYbRmUjaiJlOqq3ReB30Zgtsq2B+g2Q0cLUlm91slc0boC4pPaQy1AJDh2oIQ\r\n" \
    "Zn2uVCuLZXmRoeJhw81ASQjuaAzxi4bSRr/QuKoRAx5/VqgaHkQYDw+Fi9qLRF7i\r\n" \
    "GMZiL8dmjfpd2H3zJ4kpAcWQDj8n8TDISg7v1t7HxydrxwU9esQCPJodPg/oNJhb\r\n" \
    "y3NLUpbYEaIsgIhpOVrTD7DeWS8Rx/fqEgEwlwIDAQABAoIBAQCXR0S8EIHFGORZ\r\n" \
    "++AtOg6eENxD+xVs0f1IeGz57Tjo3QnXX7VBZNdj+p1ECvhCE/G7XnkgU5hLZX+G\r\n" \
    "Z0jkz/tqJOI0vRSdLBbipHnWouyBQ4e/A1yIJdlBtqXxJ1KE/ituHRbNc4j4kL8Z\r\n" \
    "/r6pvwnTI0PSx2Eqs048YdS92LT6qAv4flbNDxMn2uY7s4ycS4Q8w1JXnCeaAnYm\r\n" \
    "WYI5wxO+bvRELR2Mcz5DmVnL8jRyml6l6582bSv5oufReFIbyPZbQWlXgYnpu6He\r\n" \
    "GTc7E1zKYQGG/9+DQUl/1vQuCPqQwny0tQoX2w5tdYpdMdVm+zkLtbajzdTviJJa\r\n" \
    "TWzL6lt5AoGBAN86+SVeJDcmQJcv4Eq6UhtRr4QGMiQMz0Sod6ettYxYzMgxtw28\r\n" \
    "CIrgpozCc+UaZJLo7UxvC6an85r1b2nKPCLQFaggJ0H4Q0J/sZOhBIXaoBzWxveK\r\n" \
    "nupceKdVxGsFi8CDy86DBfiyFivfBj+47BbaQzPBj7C4rK7UlLjab2rDAoGBAN2u\r\n" \
    "AM2gchoFiu4v1HFL8D7lweEpi6ZnMJjnEu/dEgGQJFjwdpLnPbsj4c75odQ4Gz8g\r\n" \
    "sw9lao9VVzbusoRE/JGI4aTdO0pATXyG7eG1Qu+5Yc1YGXcCrliA2xM9xx+d7f+s\r\n" \
    "mPzN+WIEg5GJDYZDjAzHG5BNvi/FfM1C9dOtjv2dAoGAF0t5KmwbjWHBhcVqO4Ic\r\n" \
    "BVvN3BIlc1ue2YRXEDlxY5b0r8N4XceMgKmW18OHApZxfl8uPDauWZLXOgl4uepv\r\n" \
    "whZC3EuWrSyyICNhLY21Ah7hbIEBPF3L3ZsOwC+UErL+dXWLdB56Jgy3gZaBeW7b\r\n" \
    "vDrEnocJbqCm7IukhXHOBK8CgYEAwqdHB0hqyNSzIOGY7v9abzB6pUdA3BZiQvEs\r\n" \
    "3LjHVd4HPJ2x0N8CgrBIWOE0q8+0hSMmeE96WW/7jD3fPWwCR5zlXknxBQsfv0gP\r\n" \
    "3BC5PR0Qdypz+d+9zfMf625kyit4T/hzwhDveZUzHnk1Cf+IG7Q+TOEnLnWAWBED\r\n" \
    "ISOWmrUCgYAFEmRxgwAc/u+D6t0syCwAYh6POtscq9Y0i9GyWk89NzgC4NdwwbBH\r\n" \
    "4AgahOxIxXx2gxJnq3yfkJfIjwf0s2DyP0kY2y6Ua1OeomPeY9mrIS4tCuDQ6LrE\r\n" \
    "TB6l9VGoxJL4fyHnZb8L5gGvnB1bbD8cL6YPaDiOhcRseC9vBiEuVg==\r\n"         \
    "-----END RSA PRIVATE KEY-----\r\n"
/* END FILE */

/* This was generated from tests/data_files/server2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_SRV_KEY_RSA_DER tests/data_files/server2.key.der */
#define TEST_SRV_KEY_RSA_DER {                                               \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc1, 0x4d, 0xa3, 0xdd, 0xe7, 0xcd, 0x1d, 0xd1, 0x04, 0xd7, 0x49, 0x72,  \
    0xb8, 0x99, 0xac, 0x0e, 0x78, 0xe4, 0x3a, 0x3c, 0x4a, 0xcf, 0x3a, 0x13,  \
    0x16, 0xd0, 0x5a, 0xe4, 0xcd, 0xa3, 0x00, 0x88, 0xa7, 0xee, 0x1e, 0x6b,  \
    0x96, 0xa7, 0x52, 0xb4, 0x90, 0xef, 0x2d, 0x72, 0x7a, 0x3e, 0x24, 0x9a,  \
    0xfc, 0xb6, 0x34, 0xac, 0x24, 0xf5, 0x77, 0xe0, 0x26, 0x64, 0x8c, 0x9c,  \
    0xb0, 0x28, 0x7d, 0xa1, 0xda, 0xea, 0x8c, 0xe6, 0xc9, 0x1c, 0x96, 0xbc,  \
    0xfe, 0xc1, 0x04, 0x52, 0xb3, 0x36, 0xd4, 0xa3, 0xfa, 0xe1, 0xb1, 0x76,  \
    0xd8, 0x90, 0xc1, 0x61, 0xb4, 0x66, 0x52, 0x36, 0xa2, 0x26, 0x53, 0xaa,  \
    0xab, 0x74, 0x5e, 0x07, 0x7d, 0x19, 0x82, 0xdb, 0x2a, 0xd8, 0x1f, 0xa0,  \
    0xd9, 0x0d, 0x1c, 0x2d, 0x49, 0x66, 0xf7, 0x5b, 0x25, 0x73, 0x46, 0xe8,  \
    0x0b, 0x8a, 0x4f, 0x69, 0x0c, 0xb5, 0x00, 0x90, 0xe1, 0xda, 0x82, 0x10,  \
    0x66, 0x7d, 0xae, 0x54, 0x2b, 0x8b, 0x65, 0x79, 0x91, 0xa1, 0xe2, 0x61,  \
    0xc3, 0xcd, 0x40, 0x49, 0x08, 0xee, 0x68, 0x0c, 0xf1, 0x8b, 0x86, 0xd2,  \
    0x46, 0xbf, 0xd0, 0xb8, 0xaa, 0x11, 0x03, 0x1e, 0x7f, 0x56, 0xa8, 0x1a,  \
    0x1e, 0x44, 0x18, 0x0f, 0x0f, 0x85, 0x8b, 0xda, 0x8b, 0x44, 0x5e, 0xe2,  \
    0x18, 0xc6, 0x62, 0x2f, 0xc7, 0x66, 0x8d, 0xfa, 0x5d, 0xd8, 0x7d, 0xf3,  \
    0x27, 0x89, 0x29, 0x01, 0xc5, 0x90, 0x0e, 0x3f, 0x27, 0xf1, 0x30, 0xc8,  \
    0x4a, 0x0e, 0xef, 0xd6, 0xde, 0xc7, 0xc7, 0x27, 0x6b, 0xc7, 0x05, 0x3d,  \
    0x7a, 0xc4, 0x02, 0x3c, 0x9a, 0x1d, 0x3e, 0x0f, 0xe8, 0x34, 0x98, 0x5b,  \
    0xcb, 0x73, 0x4b, 0x52, 0x96, 0xd8, 0x11, 0xa2, 0x2c, 0x80, 0x88, 0x69,  \
    0x39, 0x5a, 0xd3, 0x0f, 0xb0, 0xde, 0x59, 0x2f, 0x11, 0xc7, 0xf7, 0xea,  \
    0x12, 0x01, 0x30, 0x97, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x01, 0x00, 0x97, 0x47, 0x44, 0xbc, 0x10, 0x81, 0xc5, 0x18, 0xe4, 0x59,  \
    0xfb, 0xe0, 0x2d, 0x3a, 0x0e, 0x9e, 0x10, 0xdc, 0x43, 0xfb, 0x15, 0x6c,  \
    0xd1, 0xfd, 0x48, 0x78, 0x6c, 0xf9, 0xed, 0x38, 0xe8, 0xdd, 0x09, 0xd7,  \
    0x5f, 0xb5, 0x41, 0x64, 0xd7, 0x63, 0xfa, 0x9d, 0x44, 0x0a, 0xf8, 0x42,  \
    0x13, 0xf1, 0xbb, 0x5e, 0x79, 0x20, 0x53, 0x98, 0x4b, 0x65, 0x7f, 0x86,  \
    0x67, 0x48, 0xe4, 0xcf, 0xfb, 0x6a, 0x24, 0xe2, 0x34, 0xbd, 0x14, 0x9d,  \
    0x2c, 0x16, 0xe2, 0xa4, 0x79, 0xd6, 0xa2, 0xec, 0x81, 0x43, 0x87, 0xbf,  \
    0x03, 0x5c, 0x88, 0x25, 0xd9, 0x41, 0xb6, 0xa5, 0xf1, 0x27, 0x52, 0x84,  \
    0xfe, 0x2b, 0x6e, 0x1d, 0x16, 0xcd, 0x73, 0x88, 0xf8, 0x90, 0xbf, 0x19,  \
    0xfe, 0xbe, 0xa9, 0xbf, 0x09, 0xd3, 0x23, 0x43, 0xd2, 0xc7, 0x61, 0x2a,  \
    0xb3, 0x4e, 0x3c, 0x61, 0xd4, 0xbd, 0xd8, 0xb4, 0xfa, 0xa8, 0x0b, 0xf8,  \
    0x7e, 0x56, 0xcd, 0x0f, 0x13, 0x27, 0xda, 0xe6, 0x3b, 0xb3, 0x8c, 0x9c,  \
    0x4b, 0x84, 0x3c, 0xc3, 0x52, 0x57, 0x9c, 0x27, 0x9a, 0x02, 0x76, 0x26,  \
    0x59, 0x82, 0x39, 0xc3, 0x13, 0xbe, 0x6e, 0xf4, 0x44, 0x2d, 0x1d, 0x8c,  \
    0x73, 0x3e, 0x43, 0x99, 0x59, 0xcb, 0xf2, 0x34, 0x72, 0x9a, 0x5e, 0xa5,  \
    0xeb, 0x9f, 0x36, 0x6d, 0x2b, 0xf9, 0xa2, 0xe7, 0xd1, 0x78, 0x52, 0x1b,  \
    0xc8, 0xf6, 0x5b, 0x41, 0x69, 0x57, 0x81, 0x89, 0xe9, 0xbb, 0xa1, 0xde,  \
    0x19, 0x37, 0x3b, 0x13, 0x5c, 0xca, 0x61, 0x01, 0x86, 0xff, 0xdf, 0x83,  \
    0x41, 0x49, 0x7f, 0xd6, 0xf4, 0x2e, 0x08, 0xfa, 0x90, 0xc2, 0x7c, 0xb4,  \
    0xb5, 0x0a, 0x17, 0xdb, 0x0e, 0x6d, 0x75, 0x8a, 0x5d, 0x31, 0xd5, 0x66,  \
    0xfb, 0x39, 0x0b, 0xb5, 0xb6, 0xa3, 0xcd, 0xd4, 0xef, 0x88, 0x92, 0x5a,  \
    0x4d, 0x6c, 0xcb, 0xea, 0x5b, 0x79, 0x02, 0x81, 0x81, 0x00, 0xdf, 0x3a,  \
    0xf9, 0x25, 0x5e, 0x24, 0x37, 0x26, 0x40, 0x97, 0x2f, 0xe0, 0x4a, 0xba,  \
    0x52, 0x1b, 0x51, 0xaf, 0x84, 0x06, 0x32, 0x24, 0x0c, 0xcf, 0x44, 0xa8,  \
    0x77, 0xa7, 0xad, 0xb5, 0x8c, 0x58, 0xcc, 0xc8, 0x31, 0xb7, 0x0d, 0xbc,  \
    0x08, 0x8a, 0xe0, 0xa6, 0x8c, 0xc2, 0x73, 0xe5, 0x1a, 0x64, 0x92, 0xe8,  \
    0xed, 0x4c, 0x6f, 0x0b, 0xa6, 0xa7, 0xf3, 0x9a, 0xf5, 0x6f, 0x69, 0xca,  \
    0x3c, 0x22, 0xd0, 0x15, 0xa8, 0x20, 0x27, 0x41, 0xf8, 0x43, 0x42, 0x7f,  \
    0xb1, 0x93, 0xa1, 0x04, 0x85, 0xda, 0xa0, 0x1c, 0xd6, 0xc6, 0xf7, 0x8a,  \
    0x9e, 0xea, 0x5c, 0x78, 0xa7, 0x55, 0xc4, 0x6b, 0x05, 0x8b, 0xc0, 0x83,  \
    0xcb, 0xce, 0x83, 0x05, 0xf8, 0xb2, 0x16, 0x2b, 0xdf, 0x06, 0x3f, 0xb8,  \
    0xec, 0x16, 0xda, 0x43, 0x33, 0xc1, 0x8f, 0xb0, 0xb8, 0xac, 0xae, 0xd4,  \
    0x94, 0xb8, 0xda, 0x6f, 0x6a, 0xc3, 0x02, 0x81, 0x81, 0x00, 0xdd, 0xae,  \
    0x00, 0xcd, 0xa0, 0x72, 0x1a, 0x05, 0x8a, 0xee, 0x2f, 0xd4, 0x71, 0x4b,  \
    0xf0, 0x3e, 0xe5, 0xc1, 0xe1, 0x29, 0x8b, 0xa6, 0x67, 0x30, 0x98, 0xe7,  \
    0x12, 0xef, 0xdd, 0x12, 0x01, 0x90, 0x24, 0x58, 0xf0, 0x76, 0x92, 0xe7,  \
    0x3d, 0xbb, 0x23, 0xe1, 0xce, 0xf9, 0xa1, 0xd4, 0x38, 0x1b, 0x3f, 0x20,  \
    0xb3, 0x0f, 0x65, 0x6a, 0x8f, 0x55, 0x57, 0x36, 0xee, 0xb2, 0x84, 0x44,  \
    0xfc, 0x91, 0x88, 0xe1, 0xa4, 0xdd, 0x3b, 0x4a, 0x40, 0x4d, 0x7c, 0x86,  \
    0xed, 0xe1, 0xb5, 0x42, 0xef, 0xb9, 0x61, 0xcd, 0x58, 0x19, 0x77, 0x02,  \
    0xae, 0x58, 0x80, 0xdb, 0x13, 0x3d, 0xc7, 0x1f, 0x9d, 0xed, 0xff, 0xac,  \
    0x98, 0xfc, 0xcd, 0xf9, 0x62, 0x04, 0x83, 0x91, 0x89, 0x0d, 0x86, 0x43,  \
    0x8c, 0x0c, 0xc7, 0x1b, 0x90, 0x4d, 0xbe, 0x2f, 0xc5, 0x7c, 0xcd, 0x42,  \
    0xf5, 0xd3, 0xad, 0x8e, 0xfd, 0x9d, 0x02, 0x81, 0x80, 0x17, 0x4b, 0x79,  \
    0x2a, 0x6c, 0x1b, 0x8d, 0x61, 0xc1, 0x85, 0xc5, 0x6a, 0x3b, 0x82, 0x1c,  \
    0x05, 0x5b, 0xcd, 0xdc, 0x12, 0x25, 0x73, 0x5b, 0x9e, 0xd9, 0x84, 0x57,  \
    0x10, 0x39, 0x71, 0x63, 0x96, 0xf4, 0xaf, 0xc3, 0x78, 0x5d, 0xc7, 0x8c,  \
    0x80, 0xa9, 0x96, 0xd7, 0xc3, 0x87, 0x02, 0x96, 0x71, 0x7e, 0x5f, 0x2e,  \
    0x3c, 0x36, 0xae, 0x59, 0x92, 0xd7, 0x3a, 0x09, 0x78, 0xb9, 0xea, 0x6f,  \
    0xc2, 0x16, 0x42, 0xdc, 0x4b, 0x96, 0xad, 0x2c, 0xb2, 0x20, 0x23, 0x61,  \
    0x2d, 0x8d, 0xb5, 0x02, 0x1e, 0xe1, 0x6c, 0x81, 0x01, 0x3c, 0x5d, 0xcb,  \
    0xdd, 0x9b, 0x0e, 0xc0, 0x2f, 0x94, 0x12, 0xb2, 0xfe, 0x75, 0x75, 0x8b,  \
    0x74, 0x1e, 0x7a, 0x26, 0x0c, 0xb7, 0x81, 0x96, 0x81, 0x79, 0x6e, 0xdb,  \
    0xbc, 0x3a, 0xc4, 0x9e, 0x87, 0x09, 0x6e, 0xa0, 0xa6, 0xec, 0x8b, 0xa4,  \
    0x85, 0x71, 0xce, 0x04, 0xaf, 0x02, 0x81, 0x81, 0x00, 0xc2, 0xa7, 0x47,  \
    0x07, 0x48, 0x6a, 0xc8, 0xd4, 0xb3, 0x20, 0xe1, 0x98, 0xee, 0xff, 0x5a,  \
    0x6f, 0x30, 0x7a, 0xa5, 0x47, 0x40, 0xdc, 0x16, 0x62, 0x42, 0xf1, 0x2c,  \
    0xdc, 0xb8, 0xc7, 0x55, 0xde, 0x07, 0x3c, 0x9d, 0xb1, 0xd0, 0xdf, 0x02,  \
    0x82, 0xb0, 0x48, 0x58, 0xe1, 0x34, 0xab, 0xcf, 0xb4, 0x85, 0x23, 0x26,  \
    0x78, 0x4f, 0x7a, 0x59, 0x6f, 0xfb, 0x8c, 0x3d, 0xdf, 0x3d, 0x6c, 0x02,  \
    0x47, 0x9c, 0xe5, 0x5e, 0x49, 0xf1, 0x05, 0x0b, 0x1f, 0xbf, 0x48, 0x0f,  \
    0xdc, 0x10, 0xb9, 0x3d, 0x1d, 0x10, 0x77, 0x2a, 0x73, 0xf9, 0xdf, 0xbd,  \
    0xcd, 0xf3, 0x1f, 0xeb, 0x6e, 0x64, 0xca, 0x2b, 0x78, 0x4f, 0xf8, 0x73,  \
    0xc2, 0x10, 0xef, 0x79, 0x95, 0x33, 0x1e, 0x79, 0x35, 0x09, 0xff, 0x88,  \
    0x1b, 0xb4, 0x3e, 0x4c, 0xe1, 0x27, 0x2e, 0x75, 0x80, 0x58, 0x11, 0x03,  \
    0x21, 0x23, 0x96, 0x9a, 0xb5, 0x02, 0x81, 0x80, 0x05, 0x12, 0x64, 0x71,  \
    0x83, 0x00, 0x1c, 0xfe, 0xef, 0x83, 0xea, 0xdd, 0x2c, 0xc8, 0x2c, 0x00,  \
    0x62, 0x1e, 0x8f, 0x3a, 0xdb, 0x1c, 0xab, 0xd6, 0x34, 0x8b, 0xd1, 0xb2,  \
    0x5a, 0x4f, 0x3d, 0x37, 0x38, 0x02, 0xe0, 0xd7, 0x70, 0xc1, 0xb0, 0x47,  \
    0xe0, 0x08, 0x1a, 0x84, 0xec, 0x48, 0xc5, 0x7c, 0x76, 0x83, 0x12, 0x67,  \
    0xab, 0x7c, 0x9f, 0x90, 0x97, 0xc8, 0x8f, 0x07, 0xf4, 0xb3, 0x60, 0xf2,  \
    0x3f, 0x49, 0x18, 0xdb, 0x2e, 0x94, 0x6b, 0x53, 0x9e, 0xa2, 0x63, 0xde,  \
    0x63, 0xd9, 0xab, 0x21, 0x2e, 0x2d, 0x0a, 0xe0, 0xd0, 0xe8, 0xba, 0xc4,  \
    0x4c, 0x1e, 0xa5, 0xf5, 0x51, 0xa8, 0xc4, 0x92, 0xf8, 0x7f, 0x21, 0xe7,  \
    0x65, 0xbf, 0x0b, 0xe6, 0x01, 0xaf, 0x9c, 0x1d, 0x5b, 0x6c, 0x3f, 0x1c,  \
    0x2f, 0xa6, 0x0f, 0x68, 0x38, 0x8e, 0x85, 0xc4, 0x6c, 0x78, 0x2f, 0x6f,  \
    0x06, 0x21, 0x2e, 0x56                                                   \
}
/* END FILE */

/*
 * Test client Certificates
 *
 * Test client certificates are defined for each choice
 * of the following parameters:
 * - PEM or DER encoding
 * - RSA or EC key
 *
 * Things to add:
 * - hash type
 * - multiple EC curve types
 */

/* This is taken from tests/data_files/cli2.crt. */
/* BEGIN FILE string macro TEST_CLI_CRT_EC_PEM tests/data_files/cli2.crt */
#define TEST_CLI_CRT_EC_PEM                                                \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIB3zCCAWOgAwIBAgIBDTAMBggqhkjOPQQDAgUAMD4xCzAJBgNVBAYTAk5MMREw\r\n" \
    "DwYDVQQKDAhQb2xhclNTTDEcMBoGA1UEAwwTUG9sYXJTU0wgVGVzdCBFQyBDQTAe\r\n" \
    "Fw0xOTAyMTAxNDQ0MDBaFw0yOTAyMTAxNDQ0MDBaMEExCzAJBgNVBAYTAk5MMREw\r\n" \
    "DwYDVQQKDAhQb2xhclNTTDEfMB0GA1UEAwwWUG9sYXJTU0wgVGVzdCBDbGllbnQg\r\n" \
    "MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFflrrFz39Osu5O4gf8Sru7mU6zO\r\n" \
    "VVP2NA7MLuNjJQvfmOLzXGA2lsDVGBRw5X+f1UtFGOWwbNVc+JaPh3Cj5MejTTBL\r\n" \
    "MAkGA1UdEwQCMAAwHQYDVR0OBBYEFHoAX4Zk/OBd5REQO7LmO8QmP8/iMB8GA1Ud\r\n" \
    "IwQYMBaAFJ1tICRJAT8ry3i1Gbx+JMnb+zZ8MAwGCCqGSM49BAMCBQADaAAwZQIx\r\n" \
    "AMqme4DKMldUlplDET9Q6Eptre7uUWKhsLOF+zPkKDlfzpIkJYEFgcloDHGYw80u\r\n" \
    "IgIwNftyPXsabTqMM7iEHgVpX/GRozKklY9yQI/5eoA6gGW7Y+imuGR/oao5ySOb\r\n" \
    "a9Vk\r\n"                                                             \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/cli2.crt.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_CRT_EC_DER tests/data_files/cli2.crt.der */
#define TEST_CLI_CRT_EC_DER {                                                \
  0x30, 0x82, 0x01, 0xdf, 0x30, 0x82, 0x01, 0x63, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x0d, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,    \
  0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09,    \
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,    \
  0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61,    \
  0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,    \
  0x03, 0x0c, 0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20,    \
  0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e,    \
  0x17, 0x0d, 0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34,    \
  0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31,    \
  0x34, 0x34, 0x34, 0x30, 0x30, 0x5a, 0x30, 0x41, 0x31, 0x0b, 0x30, 0x09,    \
  0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30,    \
  0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61,    \
  0x72, 0x53, 0x53, 0x4c, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,    \
  0x03, 0x0c, 0x16, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20,    \
  0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20,    \
  0x32, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,    \
  0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,    \
  0x03, 0x42, 0x00, 0x04, 0x57, 0xe5, 0xae, 0xb1, 0x73, 0xdf, 0xd3, 0xac,    \
  0xbb, 0x93, 0xb8, 0x81, 0xff, 0x12, 0xae, 0xee, 0xe6, 0x53, 0xac, 0xce,    \
  0x55, 0x53, 0xf6, 0x34, 0x0e, 0xcc, 0x2e, 0xe3, 0x63, 0x25, 0x0b, 0xdf,    \
  0x98, 0xe2, 0xf3, 0x5c, 0x60, 0x36, 0x96, 0xc0, 0xd5, 0x18, 0x14, 0x70,    \
  0xe5, 0x7f, 0x9f, 0xd5, 0x4b, 0x45, 0x18, 0xe5, 0xb0, 0x6c, 0xd5, 0x5c,    \
  0xf8, 0x96, 0x8f, 0x87, 0x70, 0xa3, 0xe4, 0xc7, 0xa3, 0x4d, 0x30, 0x4b,    \
  0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,    \
  0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x7a, 0x00,    \
  0x5f, 0x86, 0x64, 0xfc, 0xe0, 0x5d, 0xe5, 0x11, 0x10, 0x3b, 0xb2, 0xe6,    \
  0x3b, 0xc4, 0x26, 0x3f, 0xcf, 0xe2, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,    \
  0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24, 0x49,    \
  0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb,    \
  0xfb, 0x36, 0x7c, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,    \
  0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31,    \
  0x00, 0xca, 0xa6, 0x7b, 0x80, 0xca, 0x32, 0x57, 0x54, 0x96, 0x99, 0x43,    \
  0x11, 0x3f, 0x50, 0xe8, 0x4a, 0x6d, 0xad, 0xee, 0xee, 0x51, 0x62, 0xa1,    \
  0xb0, 0xb3, 0x85, 0xfb, 0x33, 0xe4, 0x28, 0x39, 0x5f, 0xce, 0x92, 0x24,    \
  0x25, 0x81, 0x05, 0x81, 0xc9, 0x68, 0x0c, 0x71, 0x98, 0xc3, 0xcd, 0x2e,    \
  0x22, 0x02, 0x30, 0x35, 0xfb, 0x72, 0x3d, 0x7b, 0x1a, 0x6d, 0x3a, 0x8c,    \
  0x33, 0xb8, 0x84, 0x1e, 0x05, 0x69, 0x5f, 0xf1, 0x91, 0xa3, 0x32, 0xa4,    \
  0x95, 0x8f, 0x72, 0x40, 0x8f, 0xf9, 0x7a, 0x80, 0x3a, 0x80, 0x65, 0xbb,    \
  0x63, 0xe8, 0xa6, 0xb8, 0x64, 0x7f, 0xa1, 0xaa, 0x39, 0xc9, 0x23, 0x9b,    \
  0x6b, 0xd5, 0x64                                                           \
}
/* END FILE */

/* This is taken from tests/data_files/cli2.key. */
/* BEGIN FILE string macro TEST_CLI_KEY_EC_PEM tests/data_files/cli2.key */
#define TEST_CLI_KEY_EC_PEM                                                \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "MHcCAQEEIPb3hmTxZ3/mZI3vyk7p3U3wBf+WIop6hDhkFzJhmLcqoAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAEV+WusXPf06y7k7iB/xKu7uZTrM5VU/Y0Dswu42MlC9+Y4vNcYDaW\r\n" \
    "wNUYFHDlf5/VS0UY5bBs1Vz4lo+HcKPkxw==\r\n"                             \
    "-----END EC PRIVATE KEY-----\r\n"
/* END FILE */

/* This is generated from tests/data_files/cli2.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_KEY_EC_DER tests/data_files/cli2.key.der */
#define TEST_CLI_KEY_EC_DER {                                                \
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xf6, 0xf7, 0x86, 0x64, 0xf1,  \
    0x67, 0x7f, 0xe6, 0x64, 0x8d, 0xef, 0xca, 0x4e, 0xe9, 0xdd, 0x4d, 0xf0,  \
    0x05, 0xff, 0x96, 0x22, 0x8a, 0x7a, 0x84, 0x38, 0x64, 0x17, 0x32, 0x61,  \
    0x98, 0xb7, 0x2a, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,  \
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x57, 0xe5, 0xae,  \
    0xb1, 0x73, 0xdf, 0xd3, 0xac, 0xbb, 0x93, 0xb8, 0x81, 0xff, 0x12, 0xae,  \
    0xee, 0xe6, 0x53, 0xac, 0xce, 0x55, 0x53, 0xf6, 0x34, 0x0e, 0xcc, 0x2e,  \
    0xe3, 0x63, 0x25, 0x0b, 0xdf, 0x98, 0xe2, 0xf3, 0x5c, 0x60, 0x36, 0x96,  \
    0xc0, 0xd5, 0x18, 0x14, 0x70, 0xe5, 0x7f, 0x9f, 0xd5, 0x4b, 0x45, 0x18,  \
    0xe5, 0xb0, 0x6c, 0xd5, 0x5c, 0xf8, 0x96, 0x8f, 0x87, 0x70, 0xa3, 0xe4,  \
    0xc7                                                                     \
}
/* END FILE */

/* This is taken from tests/data_files/cli-rsa-sha256.crt. */
/* BEGIN FILE string macro TEST_CLI_CRT_RSA_PEM tests/data_files/cli-rsa-sha256.crt */
#define TEST_CLI_CRT_RSA_PEM                                               \
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIIDPzCCAiegAwIBAgIBBDANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n" \
    "MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n" \
    "MTkwMjEwMTQ0NDA2WhcNMjkwMjEwMTQ0NDA2WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n" \
    "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6f\r\n" \
    "M60Nj4o8VmXl3ETZzGaFB9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu\r\n" \
    "1C93KYRhTYJQj6eVSHD1bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEw\r\n" \
    "MjDV0/YI0FZPRo7yX/k9Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v\r\n" \
    "4Jv4EFbMs44TFeY0BGbH7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx/\r\n" \
    "/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB\r\n" \
    "o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBRxoQBzckAvVHZeM/xSj7zx3WtGITAf\r\n" \
    "BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQsFAAOC\r\n" \
    "AQEAXidv1d4pLlBiKWED95rMycBdgDcgyNqJxakFkRfRyA2y1mlyTn7uBXRkNLY5\r\n" \
    "ZFzK82GCjk2Q2OD4RZSCPAJJqLpHHU34t71ciffvy2KK81YvrxczRhMAE64i+qna\r\n" \
    "yP3Td2XuWJR05PVPoSemsNELs9gWttdnYy3ce+EY2Y0n7Rsi7982EeLIAA7H6ca4\r\n" \
    "2Es/NUH//JZJT32OP0doMxeDRA+vplkKqTLLWf7dX26LIriBkBaRCgR5Yv9LBPFc\r\n" \
    "NOtpzu/LbrY7QFXKJMI+JXDudCsOn8KCmiA4d6Emisqfh3V3485l7HEQNcvLTxlD\r\n" \
    "6zDQyi0/ykYUYZkwQTK1N2Nvlw==\r\n"                                     \
    "-----END CERTIFICATE-----\r\n"
/* END FILE */

/* This was generated from tests/data_files/cli-rsa-sha256.crt.der
   using `xxd -i.` */
/* BEGIN FILE binary macro TEST_CLI_CRT_RSA_DER tests/data_files/cli-rsa-sha256.crt.der */
#define TEST_CLI_CRT_RSA_DER {                                               \
  0x30, 0x82, 0x03, 0x3f, 0x30, 0x82, 0x02, 0x27, 0xa0, 0x03, 0x02, 0x01,    \
  0x02, 0x02, 0x01, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,    \
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3b, 0x31, 0x0b, 0x30,    \
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11,    \
  0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c,    \
  0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,    \
  0x04, 0x03, 0x0c, 0x10, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c,    \
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,    \
  0x31, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x36,    \
  0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34,    \
  0x34, 0x30, 0x36, 0x5a, 0x30, 0x3c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,    \
  0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06,    \
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53,    \
  0x53, 0x4c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,    \
  0x11, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x43, 0x6c,    \
  0x69, 0x65, 0x6e, 0x74, 0x20, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,    \
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,    \
  0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,    \
  0x01, 0x01, 0x00, 0xc8, 0x74, 0xc4, 0xcc, 0xb9, 0xf9, 0xb5, 0x79, 0xe9,    \
  0x45, 0xd9, 0x14, 0x60, 0xb0, 0x7d, 0xbb, 0x93, 0xf2, 0x6b, 0x1e, 0x9f,    \
  0x33, 0xad, 0x0d, 0x8f, 0x8a, 0x3c, 0x56, 0x65, 0xe5, 0xdc, 0x44, 0xd9,    \
  0xcc, 0x66, 0x85, 0x07, 0xd5, 0xf8, 0x27, 0xb0, 0x4a, 0x35, 0xd0, 0x63,    \
  0x9e, 0x0a, 0x6e, 0x1b, 0xb7, 0xda, 0xf0, 0x7e, 0xab, 0xee, 0x0c, 0x10,    \
  0x93, 0x86, 0x49, 0x18, 0x34, 0xf3, 0xa8, 0x2a, 0xd2, 0x57, 0xf5, 0x2e,    \
  0xd4, 0x2f, 0x77, 0x29, 0x84, 0x61, 0x4d, 0x82, 0x50, 0x8f, 0xa7, 0x95,    \
  0x48, 0x70, 0xf5, 0x6e, 0x4d, 0xb2, 0xd5, 0x13, 0xc3, 0xd2, 0x1a, 0xed,    \
  0xe6, 0x43, 0xea, 0x42, 0x14, 0xeb, 0x74, 0xea, 0xc0, 0xed, 0x1f, 0xd4,    \
  0x57, 0x4e, 0xa9, 0xf3, 0xa8, 0xed, 0xd2, 0xe0, 0xc1, 0x30, 0x71, 0x30,    \
  0x32, 0x30, 0xd5, 0xd3, 0xf6, 0x08, 0xd0, 0x56, 0x4f, 0x46, 0x8e, 0xf2,    \
  0x5f, 0xf9, 0x3d, 0x67, 0x91, 0x88, 0x30, 0x2e, 0x42, 0xb2, 0xdf, 0x7d,    \
  0xfb, 0xe5, 0x0c, 0x77, 0xff, 0xec, 0x31, 0xc0, 0x78, 0x8f, 0xbf, 0xc2,    \
  0x7f, 0xca, 0xad, 0x6c, 0x21, 0xd6, 0x8d, 0xd9, 0x8b, 0x6a, 0x8e, 0x6f,    \
  0xe0, 0x9b, 0xf8, 0x10, 0x56, 0xcc, 0xb3, 0x8e, 0x13, 0x15, 0xe6, 0x34,    \
  0x04, 0x66, 0xc7, 0xee, 0xf9, 0x36, 0x0e, 0x6a, 0x95, 0xf6, 0x09, 0x9a,    \
  0x06, 0x67, 0xf4, 0x65, 0x71, 0xf8, 0xca, 0xa4, 0xb1, 0x25, 0xe0, 0xfe,    \
  0x3c, 0x8b, 0x35, 0x04, 0x67, 0xba, 0xe0, 0x4f, 0x76, 0x85, 0xfc, 0x7f,    \
  0xfc, 0x36, 0x6b, 0xb5, 0xe9, 0xcd, 0x2d, 0x03, 0x62, 0x4e, 0xb3, 0x3d,    \
  0x00, 0xcf, 0xaf, 0x76, 0xa0, 0x69, 0x56, 0x83, 0x6a, 0xd2, 0xa8, 0xd4,    \
  0xe7, 0x50, 0x71, 0xe6, 0xb5, 0x36, 0x05, 0x77, 0x05, 0x6d, 0x7b, 0xc8,    \
  0xe4, 0xc4, 0xfd, 0x4c, 0xd5, 0x21, 0x5f, 0x02, 0x03, 0x01, 0x00, 0x01,    \
  0xa3, 0x4d, 0x30, 0x4b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,    \
  0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,    \
  0x04, 0x14, 0x71, 0xa1, 0x00, 0x73, 0x72, 0x40, 0x2f, 0x54, 0x76, 0x5e,    \
  0x33, 0xfc, 0x52, 0x8f, 0xbc, 0xf1, 0xdd, 0x6b, 0x46, 0x21, 0x30, 0x1f,    \
  0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb4,    \
  0x5a, 0xe4, 0xa5, 0xb3, 0xde, 0xd2, 0x52, 0xf6, 0xb9, 0xd5, 0xa6, 0x95,    \
  0x0f, 0xeb, 0x3e, 0xbc, 0xc7, 0xfd, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,    \
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,    \
  0x01, 0x01, 0x00, 0x5e, 0x27, 0x6f, 0xd5, 0xde, 0x29, 0x2e, 0x50, 0x62,    \
  0x29, 0x61, 0x03, 0xf7, 0x9a, 0xcc, 0xc9, 0xc0, 0x5d, 0x80, 0x37, 0x20,    \
  0xc8, 0xda, 0x89, 0xc5, 0xa9, 0x05, 0x91, 0x17, 0xd1, 0xc8, 0x0d, 0xb2,    \
  0xd6, 0x69, 0x72, 0x4e, 0x7e, 0xee, 0x05, 0x74, 0x64, 0x34, 0xb6, 0x39,    \
  0x64, 0x5c, 0xca, 0xf3, 0x61, 0x82, 0x8e, 0x4d, 0x90, 0xd8, 0xe0, 0xf8,    \
  0x45, 0x94, 0x82, 0x3c, 0x02, 0x49, 0xa8, 0xba, 0x47, 0x1d, 0x4d, 0xf8,    \
  0xb7, 0xbd, 0x5c, 0x89, 0xf7, 0xef, 0xcb, 0x62, 0x8a, 0xf3, 0x56, 0x2f,    \
  0xaf, 0x17, 0x33, 0x46, 0x13, 0x00, 0x13, 0xae, 0x22, 0xfa, 0xa9, 0xda,    \
  0xc8, 0xfd, 0xd3, 0x77, 0x65, 0xee, 0x58, 0x94, 0x74, 0xe4, 0xf5, 0x4f,    \
  0xa1, 0x27, 0xa6, 0xb0, 0xd1, 0x0b, 0xb3, 0xd8, 0x16, 0xb6, 0xd7, 0x67,    \
  0x63, 0x2d, 0xdc, 0x7b, 0xe1, 0x18, 0xd9, 0x8d, 0x27, 0xed, 0x1b, 0x22,    \
  0xef, 0xdf, 0x36, 0x11, 0xe2, 0xc8, 0x00, 0x0e, 0xc7, 0xe9, 0xc6, 0xb8,    \
  0xd8, 0x4b, 0x3f, 0x35, 0x41, 0xff, 0xfc, 0x96, 0x49, 0x4f, 0x7d, 0x8e,    \
  0x3f, 0x47, 0x68, 0x33, 0x17, 0x83, 0x44, 0x0f, 0xaf, 0xa6, 0x59, 0x0a,    \
  0xa9, 0x32, 0xcb, 0x59, 0xfe, 0xdd, 0x5f, 0x6e, 0x8b, 0x22, 0xb8, 0x81,    \
  0x90, 0x16, 0x91, 0x0a, 0x04, 0x79, 0x62, 0xff, 0x4b, 0x04, 0xf1, 0x5c,    \
  0x34, 0xeb, 0x69, 0xce, 0xef, 0xcb, 0x6e, 0xb6, 0x3b, 0x40, 0x55, 0xca,    \
  0x24, 0xc2, 0x3e, 0x25, 0x70, 0xee, 0x74, 0x2b, 0x0e, 0x9f, 0xc2, 0x82,    \
  0x9a, 0x20, 0x38, 0x77, 0xa1, 0x26, 0x8a, 0xca, 0x9f, 0x87, 0x75, 0x77,    \
  0xe3, 0xce, 0x65, 0xec, 0x71, 0x10, 0x35, 0xcb, 0xcb, 0x4f, 0x19, 0x43,    \
  0xeb, 0x30, 0xd0, 0xca, 0x2d, 0x3f, 0xca, 0x46, 0x14, 0x61, 0x99, 0x30,    \
  0x41, 0x32, 0xb5, 0x37, 0x63, 0x6f, 0x97                                   \
}
/* END FILE */

/* This is taken from tests/data_files/cli-rsa.key. */
/* BEGIN FILE string macro TEST_CLI_KEY_RSA_PEM tests/data_files/cli-rsa.key */
#define TEST_CLI_KEY_RSA_PEM                                               \
    "-----BEGIN RSA PRIVATE KEY-----\r\n"                                  \
    "MIIEpAIBAAKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6fM60Nj4o8VmXl3ETZzGaF\r\n" \
    "B9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu1C93KYRhTYJQj6eVSHD1\r\n" \
    "bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEwMjDV0/YI0FZPRo7yX/k9\r\n" \
    "Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v4Jv4EFbMs44TFeY0BGbH\r\n" \
    "7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx//DZrtenNLQNiTrM9AM+v\r\n" \
    "dqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQABAoIBAGdNtfYDiap6bzst\r\n" \
    "yhCiI8m9TtrhZw4MisaEaN/ll3XSjaOG2dvV6xMZCMV+5TeXDHOAZnY18Yi18vzz\r\n" \
    "4Ut2TnNFzizCECYNaA2fST3WgInnxUkV3YXAyP6CNxJaCmv2aA0yFr2kFVSeaKGt\r\n" \
    "ymvljNp2NVkvm7Th8fBQBO7I7AXhz43k0mR7XmPgewe8ApZOG3hstkOaMvbWAvWA\r\n" \
    "zCZupdDjZYjOJqlA4eEA4H8/w7F83r5CugeBE8LgEREjLPiyejrU5H1fubEY+h0d\r\n" \
    "l5HZBJ68ybTXfQ5U9o/QKA3dd0toBEhhdRUDGzWtjvwkEQfqF1reGWj/tod/gCpf\r\n" \
    "DFi6X0ECgYEA4wOv/pjSC3ty6TuOvKX2rOUiBrLXXv2JSxZnMoMiWI5ipLQt+RYT\r\n" \
    "VPafL/m7Dn6MbwjayOkcZhBwk5CNz5A6Q4lJ64Mq/lqHznRCQQ2Mc1G8eyDF/fYL\r\n" \
    "Ze2pLvwP9VD5jTc2miDfw+MnvJhywRRLcemDFP8k4hQVtm8PMp3ZmNECgYEA4gz7\r\n" \
    "wzObR4gn8ibe617uQPZjWzUj9dUHYd+in1gwBCIrtNnaRn9I9U/Q6tegRYpii4ys\r\n" \
    "c176NmU+umy6XmuSKV5qD9bSpZWG2nLFnslrN15Lm3fhZxoeMNhBaEDTnLT26yoi\r\n" \
    "33gp0mSSWy94ZEqipms+ULF6sY1ZtFW6tpGFoy8CgYAQHhnnvJflIs2ky4q10B60\r\n" \
    "ZcxFp3rtDpkp0JxhFLhiizFrujMtZSjYNm5U7KkgPVHhLELEUvCmOnKTt4ap/vZ0\r\n" \
    "BxJNe1GZH3pW6SAvGDQpl9sG7uu/vTFP+lCxukmzxB0DrrDcvorEkKMom7ZCCRvW\r\n" \
    "KZsZ6YeH2Z81BauRj218kQKBgQCUV/DgKP2985xDTT79N08jUo3hTP5MVYCCuj/+\r\n" \
    "UeEw1TvZcx3LJby7P6Xad6a1/BqveaGyFKIfEFIaBUBItk801sDDpDaYc4gL00Xc\r\n" \
    "7lFuBHOZkxJYlss5QrGpuOEl9ZwUt5IrFLBdYaKqNHzNVC1pCPfb/JyH6Dr2HUxq\r\n" \
    "gxUwAQKBgQCcU6G2L8AG9d9c0UpOyL1tMvFe5Ttw0KjlQVdsh1MP6yigYo9DYuwu\r\n" \
    "bHFVW2r0dBTqegP2/KTOxKzaHfC1qf0RGDsUoJCNJrd1cwoCLG8P2EF4w3OBrKqv\r\n" \
    "8u4ytY0F+Vlanj5lm3TaoHSVF1+NWPyOTiwevIECGKwSxvlki4fDAA==\r\n"         \
    "-----END RSA PRIVATE KEY-----\r\n"/* END FILE */

/* This was generated from tests/data_files/cli-rsa.key.der using `xxd -i`. */
/* BEGIN FILE binary macro TEST_CLI_KEY_RSA_DER tests/data_files/cli-rsa.key.der */
#define TEST_CLI_KEY_RSA_DER {                                               \
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,  \
    0xc8, 0x74, 0xc4, 0xcc, 0xb9, 0xf9, 0xb5, 0x79, 0xe9, 0x45, 0xd9, 0x14,  \
    0x60, 0xb0, 0x7d, 0xbb, 0x93, 0xf2, 0x6b, 0x1e, 0x9f, 0x33, 0xad, 0x0d,  \
    0x8f, 0x8a, 0x3c, 0x56, 0x65, 0xe5, 0xdc, 0x44, 0xd9, 0xcc, 0x66, 0x85,  \
    0x07, 0xd5, 0xf8, 0x27, 0xb0, 0x4a, 0x35, 0xd0, 0x63, 0x9e, 0x0a, 0x6e,  \
    0x1b, 0xb7, 0xda, 0xf0, 0x7e, 0xab, 0xee, 0x0c, 0x10, 0x93, 0x86, 0x49,  \
    0x18, 0x34, 0xf3, 0xa8, 0x2a, 0xd2, 0x57, 0xf5, 0x2e, 0xd4, 0x2f, 0x77,  \
    0x29, 0x84, 0x61, 0x4d, 0x82, 0x50, 0x8f, 0xa7, 0x95, 0x48, 0x70, 0xf5,  \
    0x6e, 0x4d, 0xb2, 0xd5, 0x13, 0xc3, 0xd2, 0x1a, 0xed, 0xe6, 0x43, 0xea,  \
    0x42, 0x14, 0xeb, 0x74, 0xea, 0xc0, 0xed, 0x1f, 0xd4, 0x57, 0x4e, 0xa9,  \
    0xf3, 0xa8, 0xed, 0xd2, 0xe0, 0xc1, 0x30, 0x71, 0x30, 0x32, 0x30, 0xd5,  \
    0xd3, 0xf6, 0x08, 0xd0, 0x56, 0x4f, 0x46, 0x8e, 0xf2, 0x5f, 0xf9, 0x3d,  \
    0x67, 0x91, 0x88, 0x30, 0x2e, 0x42, 0xb2, 0xdf, 0x7d, 0xfb, 0xe5, 0x0c,  \
    0x77, 0xff, 0xec, 0x31, 0xc0, 0x78, 0x8f, 0xbf, 0xc2, 0x7f, 0xca, 0xad,  \
    0x6c, 0x21, 0xd6, 0x8d, 0xd9, 0x8b, 0x6a, 0x8e, 0x6f, 0xe0, 0x9b, 0xf8,  \
    0x10, 0x56, 0xcc, 0xb3, 0x8e, 0x13, 0x15, 0xe6, 0x34, 0x04, 0x66, 0xc7,  \
    0xee, 0xf9, 0x36, 0x0e, 0x6a, 0x95, 0xf6, 0x09, 0x9a, 0x06, 0x67, 0xf4,  \
    0x65, 0x71, 0xf8, 0xca, 0xa4, 0xb1, 0x25, 0xe0, 0xfe, 0x3c, 0x8b, 0x35,  \
    0x04, 0x67, 0xba, 0xe0, 0x4f, 0x76, 0x85, 0xfc, 0x7f, 0xfc, 0x36, 0x6b,  \
    0xb5, 0xe9, 0xcd, 0x2d, 0x03, 0x62, 0x4e, 0xb3, 0x3d, 0x00, 0xcf, 0xaf,  \
    0x76, 0xa0, 0x69, 0x56, 0x83, 0x6a, 0xd2, 0xa8, 0xd4, 0xe7, 0x50, 0x71,  \
    0xe6, 0xb5, 0x36, 0x05, 0x77, 0x05, 0x6d, 0x7b, 0xc8, 0xe4, 0xc4, 0xfd,  \
    0x4c, 0xd5, 0x21, 0x5f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,  \
    0x00, 0x67, 0x4d, 0xb5, 0xf6, 0x03, 0x89, 0xaa, 0x7a, 0x6f, 0x3b, 0x2d,  \
    0xca, 0x10, 0xa2, 0x23, 0xc9, 0xbd, 0x4e, 0xda, 0xe1, 0x67, 0x0e, 0x0c,  \
    0x8a, 0xc6, 0x84, 0x68, 0xdf, 0xe5, 0x97, 0x75, 0xd2, 0x8d, 0xa3, 0x86,  \
    0xd9, 0xdb, 0xd5, 0xeb, 0x13, 0x19, 0x08, 0xc5, 0x7e, 0xe5, 0x37, 0x97,  \
    0x0c, 0x73, 0x80, 0x66, 0x76, 0x35, 0xf1, 0x88, 0xb5, 0xf2, 0xfc, 0xf3,  \
    0xe1, 0x4b, 0x76, 0x4e, 0x73, 0x45, 0xce, 0x2c, 0xc2, 0x10, 0x26, 0x0d,  \
    0x68, 0x0d, 0x9f, 0x49, 0x3d, 0xd6, 0x80, 0x89, 0xe7, 0xc5, 0x49, 0x15,  \
    0xdd, 0x85, 0xc0, 0xc8, 0xfe, 0x82, 0x37, 0x12, 0x5a, 0x0a, 0x6b, 0xf6,  \
    0x68, 0x0d, 0x32, 0x16, 0xbd, 0xa4, 0x15, 0x54, 0x9e, 0x68, 0xa1, 0xad,  \
    0xca, 0x6b, 0xe5, 0x8c, 0xda, 0x76, 0x35, 0x59, 0x2f, 0x9b, 0xb4, 0xe1,  \
    0xf1, 0xf0, 0x50, 0x04, 0xee, 0xc8, 0xec, 0x05, 0xe1, 0xcf, 0x8d, 0xe4,  \
    0xd2, 0x64, 0x7b, 0x5e, 0x63, 0xe0, 0x7b, 0x07, 0xbc, 0x02, 0x96, 0x4e,  \
    0x1b, 0x78, 0x6c, 0xb6, 0x43, 0x9a, 0x32, 0xf6, 0xd6, 0x02, 0xf5, 0x80,  \
    0xcc, 0x26, 0x6e, 0xa5, 0xd0, 0xe3, 0x65, 0x88, 0xce, 0x26, 0xa9, 0x40,  \
    0xe1, 0xe1, 0x00, 0xe0, 0x7f, 0x3f, 0xc3, 0xb1, 0x7c, 0xde, 0xbe, 0x42,  \
    0xba, 0x07, 0x81, 0x13, 0xc2, 0xe0, 0x11, 0x11, 0x23, 0x2c, 0xf8, 0xb2,  \
    0x7a, 0x3a, 0xd4, 0xe4, 0x7d, 0x5f, 0xb9, 0xb1, 0x18, 0xfa, 0x1d, 0x1d,  \
    0x97, 0x91, 0xd9, 0x04, 0x9e, 0xbc, 0xc9, 0xb4, 0xd7, 0x7d, 0x0e, 0x54,  \
    0xf6, 0x8f, 0xd0, 0x28, 0x0d, 0xdd, 0x77, 0x4b, 0x68, 0x04, 0x48, 0x61,  \
    0x75, 0x15, 0x03, 0x1b, 0x35, 0xad, 0x8e, 0xfc, 0x24, 0x11, 0x07, 0xea,  \
    0x17, 0x5a, 0xde, 0x19, 0x68, 0xff, 0xb6, 0x87, 0x7f, 0x80, 0x2a, 0x5f,  \
    0x0c, 0x58, 0xba, 0x5f, 0x41, 0x02, 0x81, 0x81, 0x00, 0xe3, 0x03, 0xaf,  \
    0xfe, 0x98, 0xd2, 0x0b, 0x7b, 0x72, 0xe9, 0x3b, 0x8e, 0xbc, 0xa5, 0xf6,  \
    0xac, 0xe5, 0x22, 0x06, 0xb2, 0xd7, 0x5e, 0xfd, 0x89, 0x4b, 0x16, 0x67,  \
    0x32, 0x83, 0x22, 0x58, 0x8e, 0x62, 0xa4, 0xb4, 0x2d, 0xf9, 0x16, 0x13,  \
    0x54, 0xf6, 0x9f, 0x2f, 0xf9, 0xbb, 0x0e, 0x7e, 0x8c, 0x6f, 0x08, 0xda,  \
    0xc8, 0xe9, 0x1c, 0x66, 0x10, 0x70, 0x93, 0x90, 0x8d, 0xcf, 0x90, 0x3a,  \
    0x43, 0x89, 0x49, 0xeb, 0x83, 0x2a, 0xfe, 0x5a, 0x87, 0xce, 0x74, 0x42,  \
    0x41, 0x0d, 0x8c, 0x73, 0x51, 0xbc, 0x7b, 0x20, 0xc5, 0xfd, 0xf6, 0x0b,  \
    0x65, 0xed, 0xa9, 0x2e, 0xfc, 0x0f, 0xf5, 0x50, 0xf9, 0x8d, 0x37, 0x36,  \
    0x9a, 0x20, 0xdf, 0xc3, 0xe3, 0x27, 0xbc, 0x98, 0x72, 0xc1, 0x14, 0x4b,  \
    0x71, 0xe9, 0x83, 0x14, 0xff, 0x24, 0xe2, 0x14, 0x15, 0xb6, 0x6f, 0x0f,  \
    0x32, 0x9d, 0xd9, 0x98, 0xd1, 0x02, 0x81, 0x81, 0x00, 0xe2, 0x0c, 0xfb,  \
    0xc3, 0x33, 0x9b, 0x47, 0x88, 0x27, 0xf2, 0x26, 0xde, 0xeb, 0x5e, 0xee,  \
    0x40, 0xf6, 0x63, 0x5b, 0x35, 0x23, 0xf5, 0xd5, 0x07, 0x61, 0xdf, 0xa2,  \
    0x9f, 0x58, 0x30, 0x04, 0x22, 0x2b, 0xb4, 0xd9, 0xda, 0x46, 0x7f, 0x48,  \
    0xf5, 0x4f, 0xd0, 0xea, 0xd7, 0xa0, 0x45, 0x8a, 0x62, 0x8b, 0x8c, 0xac,  \
    0x73, 0x5e, 0xfa, 0x36, 0x65, 0x3e, 0xba, 0x6c, 0xba, 0x5e, 0x6b, 0x92,  \
    0x29, 0x5e, 0x6a, 0x0f, 0xd6, 0xd2, 0xa5, 0x95, 0x86, 0xda, 0x72, 0xc5,  \
    0x9e, 0xc9, 0x6b, 0x37, 0x5e, 0x4b, 0x9b, 0x77, 0xe1, 0x67, 0x1a, 0x1e,  \
    0x30, 0xd8, 0x41, 0x68, 0x40, 0xd3, 0x9c, 0xb4, 0xf6, 0xeb, 0x2a, 0x22,  \
    0xdf, 0x78, 0x29, 0xd2, 0x64, 0x92, 0x5b, 0x2f, 0x78, 0x64, 0x4a, 0xa2,  \
    0xa6, 0x6b, 0x3e, 0x50, 0xb1, 0x7a, 0xb1, 0x8d, 0x59, 0xb4, 0x55, 0xba,  \
    0xb6, 0x91, 0x85, 0xa3, 0x2f, 0x02, 0x81, 0x80, 0x10, 0x1e, 0x19, 0xe7,  \
    0xbc, 0x97, 0xe5, 0x22, 0xcd, 0xa4, 0xcb, 0x8a, 0xb5, 0xd0, 0x1e, 0xb4,  \
    0x65, 0xcc, 0x45, 0xa7, 0x7a, 0xed, 0x0e, 0x99, 0x29, 0xd0, 0x9c, 0x61,  \
    0x14, 0xb8, 0x62, 0x8b, 0x31, 0x6b, 0xba, 0x33, 0x2d, 0x65, 0x28, 0xd8,  \
    0x36, 0x6e, 0x54, 0xec, 0xa9, 0x20, 0x3d, 0x51, 0xe1, 0x2c, 0x42, 0xc4,  \
    0x52, 0xf0, 0xa6, 0x3a, 0x72, 0x93, 0xb7, 0x86, 0xa9, 0xfe, 0xf6, 0x74,  \
    0x07, 0x12, 0x4d, 0x7b, 0x51, 0x99, 0x1f, 0x7a, 0x56, 0xe9, 0x20, 0x2f,  \
    0x18, 0x34, 0x29, 0x97, 0xdb, 0x06, 0xee, 0xeb, 0xbf, 0xbd, 0x31, 0x4f,  \
    0xfa, 0x50, 0xb1, 0xba, 0x49, 0xb3, 0xc4, 0x1d, 0x03, 0xae, 0xb0, 0xdc,  \
    0xbe, 0x8a, 0xc4, 0x90, 0xa3, 0x28, 0x9b, 0xb6, 0x42, 0x09, 0x1b, 0xd6,  \
    0x29, 0x9b, 0x19, 0xe9, 0x87, 0x87, 0xd9, 0x9f, 0x35, 0x05, 0xab, 0x91,  \
    0x8f, 0x6d, 0x7c, 0x91, 0x02, 0x81, 0x81, 0x00, 0x94, 0x57, 0xf0, 0xe0,  \
    0x28, 0xfd, 0xbd, 0xf3, 0x9c, 0x43, 0x4d, 0x3e, 0xfd, 0x37, 0x4f, 0x23,  \
    0x52, 0x8d, 0xe1, 0x4c, 0xfe, 0x4c, 0x55, 0x80, 0x82, 0xba, 0x3f, 0xfe,  \
    0x51, 0xe1, 0x30, 0xd5, 0x3b, 0xd9, 0x73, 0x1d, 0xcb, 0x25, 0xbc, 0xbb,  \
    0x3f, 0xa5, 0xda, 0x77, 0xa6, 0xb5, 0xfc, 0x1a, 0xaf, 0x79, 0xa1, 0xb2,  \
    0x14, 0xa2, 0x1f, 0x10, 0x52, 0x1a, 0x05, 0x40, 0x48, 0xb6, 0x4f, 0x34,  \
    0xd6, 0xc0, 0xc3, 0xa4, 0x36, 0x98, 0x73, 0x88, 0x0b, 0xd3, 0x45, 0xdc,  \
    0xee, 0x51, 0x6e, 0x04, 0x73, 0x99, 0x93, 0x12, 0x58, 0x96, 0xcb, 0x39,  \
    0x42, 0xb1, 0xa9, 0xb8, 0xe1, 0x25, 0xf5, 0x9c, 0x14, 0xb7, 0x92, 0x2b,  \
    0x14, 0xb0, 0x5d, 0x61, 0xa2, 0xaa, 0x34, 0x7c, 0xcd, 0x54, 0x2d, 0x69,  \
    0x08, 0xf7, 0xdb, 0xfc, 0x9c, 0x87, 0xe8, 0x3a, 0xf6, 0x1d, 0x4c, 0x6a,  \
    0x83, 0x15, 0x30, 0x01, 0x02, 0x81, 0x81, 0x00, 0x9c, 0x53, 0xa1, 0xb6,  \
    0x2f, 0xc0, 0x06, 0xf5, 0xdf, 0x5c, 0xd1, 0x4a, 0x4e, 0xc8, 0xbd, 0x6d,  \
    0x32, 0xf1, 0x5e, 0xe5, 0x3b, 0x70, 0xd0, 0xa8, 0xe5, 0x41, 0x57, 0x6c,  \
    0x87, 0x53, 0x0f, 0xeb, 0x28, 0xa0, 0x62, 0x8f, 0x43, 0x62, 0xec, 0x2e,  \
    0x6c, 0x71, 0x55, 0x5b, 0x6a, 0xf4, 0x74, 0x14, 0xea, 0x7a, 0x03, 0xf6,  \
    0xfc, 0xa4, 0xce, 0xc4, 0xac, 0xda, 0x1d, 0xf0, 0xb5, 0xa9, 0xfd, 0x11,  \
    0x18, 0x3b, 0x14, 0xa0, 0x90, 0x8d, 0x26, 0xb7, 0x75, 0x73, 0x0a, 0x02,  \
    0x2c, 0x6f, 0x0f, 0xd8, 0x41, 0x78, 0xc3, 0x73, 0x81, 0xac, 0xaa, 0xaf,  \
    0xf2, 0xee, 0x32, 0xb5, 0x8d, 0x05, 0xf9, 0x59, 0x5a, 0x9e, 0x3e, 0x65,  \
    0x9b, 0x74, 0xda, 0xa0, 0x74, 0x95, 0x17, 0x5f, 0x8d, 0x58, 0xfc, 0x8e,  \
    0x4e, 0x2c, 0x1e, 0xbc, 0x81, 0x02, 0x18, 0xac, 0x12, 0xc6, 0xf9, 0x64,  \
    0x8b, 0x87, 0xc3, 0x00                                                   \
}
/* END FILE */

/* 
    SPHINCS+ certificates
 */
#define TEST_CA_CRT_SPHINCS_SHAKE256_PEM                                \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"yHN8h3oSPSM9xmnto+pQHMU=\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"ME0EEFOHNfVX48jiVZis1OftvrgEEQCd6zws9BEKbZbT5qsirtaWBBAPQ7lBrIvM\r\n"	\
"QeDHMz52nNi3BBEAjfuOOWTjxcAVCKa7lt2hwwIBBg==\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"	

#define TEST_SRV_CRT_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"IHXbJUjgW8tcaaaJTpA=\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_CA_CRT_SPHINCS_SHA256_PEM                                  \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHA256_PEM                                 \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"ME0EEEGGqjyYvp0yp7bUVWwzHMUEEDzKMWckefNGeaJmIPBhvNEEEQD9u7vDSeTc\r\n"	\
"H0HdmntAiXirBBEA0zXHpLlS1ghPGy+l/504jgIBBg==\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_SPHINCS_SHA256_PEM                                 \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"



/*
 * Dilithium certificates
 * 
 */
 
#define TEST_CA_CRT_DILITHIUM_SHAKE256_PEM \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"	

#define TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM \
"-----BEGIN DILITHIUM PRIVATE KEY-----\r\n"	\
"MIIdKgQgKcBkMhRF0qrESb7McRGrAp5HSLWVFoLfEfbJ0il0nGoEggoAKEtKUxDF\r\n"	\
"vrbaBNIfcxbufnPNuD7Zaej+9x0pnavynveF7xOiP5HxXCafqMxy+evIgSk2ccea\r\n"	\
"c0fHkxKxPLGwDIR+bm+3vo0q1sWnPhq/AsnQA/Nz8TqQDXjNvBXxA/RD9xAib8tG\r\n"	\
"zhVkmIHbQrZnph6p75E8H70NMgKM6pWpMY6RYpcLKpu9SMP5LIbZgqzHOqdgt+Cv\r\n"	\
"nHvKmFp6c5HK9oGwvEdE9tF0uqGnAzPah344RSE3VJlGfNHnwQGnCe1Nc6qSvSmJ\r\n"	\
"kW7IoDUtZ2zyRt0I/QzkMkmiE4gNeV69U2QQcmcHs81i2dN9jRqN6bG6CQAEvuqK\r\n"	\
"mjSrBecmSPmlVJf2kO3JTcssabRBEegl1DjJxDhedSoy/lnrR9As8wCaUAN1zig8\r\n"	\
"TKQxauIJsrjSSc1NPxx0xE4T04T9rFGwb1O6mHNfaYOvC/qbZ6vdUEJgpYiLXOK6\r\n"	\
"YB58B3rFOW+/t9QStkOrynVId8yvNw8mwj5TduLqGrqkoljoBV8arYztiWaaLTDN\r\n"	\
"zJ1u758b0UQvbeKZNvafglkTiVxCxrozW0LxKEWKR/kENgQZY9luw0pZE34ENYmb\r\n"	\
"DVNopEPZuHjqo7kOtnJ6JWDnn+JDVUMYdKQgUGydTOnOMRCGFD9R1UCOo/VLRarZ\r\n"	\
"YmuU9vYeEs0ouEytuhH3s6ekI5Xfxfn7V5OzUXn7kZrXNszqwiuRdv1sE49OA5NW\r\n"	\
"6n/AlBZYA4+DByj+JxBMIbLN7JTVpCv2Me+cj0Q7MErSXD+ZcAf4ESbCl42AeZLF\r\n"	\
"X8QfSZeAsnQ1yFmEdKqYbe3JXwvpst1MNij60APga7zHBYU0KOAziFwm/LCsS9Zo\r\n"	\
"0wjvxyRvdPAeA9QBzKO4eXdbAMy94U6KNQ36Ry7zjmIFZGQ+bJn0kX7SkjeKWfsX\r\n"	\
"D8egd+XKIui67DCwhISwE3ceYdLzzZAgooTX1zB1JfC0djt5hgi6hIG5kNfgEpz6\r\n"	\
"efgb0cmM3US7/V2BKYJem4kKJ1kgxVEf2TO36vzl/XjUiUNWV1Ds4b6lvRDbDCEk\r\n"	\
"Ujm7k5NBCHn1i5dAtOoBkUewDgZQ0co2PltR4BT+MXyhlfizH5gtvAnHguMC3Z/m\r\n"	\
"ad6+H1uG2KLYhbiEt4RPVoZPr9QYukOcccQhdWX0rxbQhu5e5Fxk0tOlJjuDK3+f\r\n"	\
"GOtbzK/Mb/Bef9OSKcG4Jh01NV8gsAcrIhljKFzU3eFxupO4dMCxPUyx7FyYOX8L\r\n"	\
"C2+osdmd30cXyLU7eFzV33OFFrUwRmXhqbf9jpXIMiDOc19gyFVV/J5ys03oeeZo\r\n"	\
"G08JimD/of1Ls0zhui0x4zTQmXPd7umG1CcaXr5l6j1+lTCEOsx5aOXaEoOoUTlp\r\n"	\
"15Y+6rrMIncPzNnt2CjW3tWJkWIZu2w5fGLixLrsRl212EoVEIGbuyy9yn6kfNTu\r\n"	\
"+pL/Gil2tBo+p3Z58HbkqgxfF0C32kxRPz4QKd+1aQwezUIsg6fBwL1YYAdlmPPP\r\n"	\
"tj3wdtzvGCcMvok0Pb/VytLWEc1fXlTBRJmc/OxdWcblOzs8GD26XQEOwHfWMNNI\r\n"	\
"dtwih1jMANa6M6438E6r0uwrkFFU8sVvT/HVgOiey1K21bCtQWrqBTcTuvo4Z2vl\r\n"	\
"tM7bAumcOlFHhE5pmcDa9fG7QW3acfjDj5GqPyQTKIvgveOBpu/KKH+DNB65xEXr\r\n"	\
"Pl8iWHPWIDDg07KoL3cL9c26hLcc7vwoXATDdoFNHGOMoIjjhNwqfDw4B+HArP72\r\n"	\
"tVqXoNmxxssPVdQu9dEgYRyKrr6KBRn+NxSBRu+v6dBNBZS447P1yLUghWwDr53p\r\n"	\
"vapA/myEqpaoVAFzaDWxCqP+QPjuN3u1sP416gEyQXj3W7kbMV/X3Pd526q//oZt\r\n"	\
"le1TkV98CNn72/tEHvGNyXQ6qt9QoIU6+rnSbkK4nlRX1IbHVbESyotJbfsirw0W\r\n"	\
"vNPNChKJp1/MeeR6CYQ86uJbV0EFRqUKQKruf8L9LshHIJhEbI4A83Ss19VcFPKo\r\n"	\
"v5hx5XVYf1Dnc6v3me/ROFMMhxOqR2D+obMcMrYKnXgq0tJhIcAoANa0V+aTY+sr\r\n"	\
"WKevbRX21ywFcb4CzRa6pjjkX7Zcum5jH0J2oYwghHpFXoB+OqvB6F0ubluKZvwp\r\n"	\
"CncqmrD1xR5uqzGp43J6QMPp0Y2DCXxVMMj/dj2lN6W+abCUPmk75nB6EAkin6Ba\r\n"	\
"4fY3tRBIP6v1MUNL0EVkJg56vP41/9sSTI0awYErEtjgkDk/rrdQF+nZk3JpNMOa\r\n"	\
"3RczeG0VuccQMZeb9LqdCZpdItpccJU2vajGujpYgDDSyOw+0gKdv2gPusHpxKPY\r\n"	\
"wV2Dip08glc6/bAe4uWCsOlCbD8vISbnK3/JvpQAeNZLC99C2sJtJpIHNY1HNTmZ\r\n"	\
"7gVYtp9WtmjfgBAHdV7+0MagL9SwwI2E82NNCV57zwEpDfxnfFf6n6QEJwmG5SZS\r\n"	\
"SB2QXy6WYqVd09XSJRsilDMPeDh+VkHcZY3Y0E5ioLDix66FnipezwUImCKbTNXY\r\n"	\
"7tvy1Z8gtbx63mzVU20X+xM4QtnvRxKIFTsIz+VTczTv9utXUpZVamYVzb70jXdY\r\n"	\
"Ag9Vab6vJVPRlzCXa6hf4XLA8lPVdPiP0Klth9ObEmy+s4z6kJ1EwjPpReDtFyko\r\n"	\
"JLxd+y65nSOBSQ7tvJjsjmcnAgsV38fHnxUzqy8Ohm7hRnqrHdIB2+YqRz2dyIfz\r\n"	\
"8Kb0ErWE1Ud6GpokxKlUqiqOrX182LdWXGtZ8U8H+KQOuS7kW0QKgHzhEnKAjW8g\r\n"	\
"AxWubL0cQEIMzfEs6dt/KOuyctAkWMJX+pgWIDaz1xROTQaBcgPLGUlG7gOKghcr\r\n"	\
"TCQsmZPUE9Bchr0wo/Zvcs+fKOJZKTiVsDWcUeaBZFySse7oPoz/YPZU31UQln1+\r\n"	\
"hDzzF33Qlb9ttwqk/DS7yPxH8lyOQ1wv/LnbqL8CKRcPpeoGbPCt1lmZeYoINjCw\r\n"	\
"jry3/u1tGNFhnSWr3se66jHqwR3Qw0YS7WHDzMaSX+Ck/JMdSOLV2LOpv2n9kv6b\r\n"	\
"lQhhl2M5QrVve6xurR4/NL4PyVfAeficbukxLq3Zi3FK7JrsPiqW0Qk5lFZ9LTCd\r\n"	\
"hWz/t7fQeC7B0/oqyFLJGTo8sTUrDgpfqDVafqKTdRTPcOerErwbskTzu9CyKkpQ\r\n"	\
"YD4Cu5wptmM3AG0CRuobNlPIcNoPK8eLUfTrSObrng0/xp6AxVbftHxzR4aWgWti\r\n"	\
"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\r\n"	\
"-----END DILITHIUM PRIVATE KEY-----\r\n"	

#define TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"GgAAABoAAAAKAAAAfGgIABgRDwAY/Ol2\r\n"	\
"-----END CERTIFICATE-----\r\n"	


/*
 *
 * Test certificates and keys as C variables
 *
 */

/*
 * CA
 */
const char mbedtls_test_ca_crt_sphincs_shake256_pem[] = TEST_CA_CRT_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_ca_crt_sphincs_sha256_pem[] = TEST_CA_CRT_SPHINCS_SHA256_PEM;

const char mbedtls_test_ca_crt_dilithium_shake256_pem[] = TEST_CA_CRT_DILITHIUM_SHAKE256_PEM;

const char mbedtls_test_ca_crt_ec_pem[]           = TEST_CA_CRT_EC_PEM;
const char mbedtls_test_ca_key_ec_pem[]           = TEST_CA_KEY_EC_PEM;
const char mbedtls_test_ca_pwd_ec_pem[]           = TEST_CA_PWD_EC_PEM;
const char mbedtls_test_ca_key_rsa_pem[]          = TEST_CA_KEY_RSA_PEM;
const char mbedtls_test_ca_pwd_rsa_pem[]          = TEST_CA_PWD_RSA_PEM;
const char mbedtls_test_ca_crt_rsa_sha1_pem[]     = TEST_CA_CRT_RSA_SHA1_PEM;
const char mbedtls_test_ca_crt_rsa_sha256_pem[]   = TEST_CA_CRT_RSA_SHA256_PEM;

const unsigned char mbedtls_test_ca_crt_ec_der[]   = TEST_CA_CRT_EC_DER;
const unsigned char mbedtls_test_ca_key_ec_der[]   = TEST_CA_KEY_EC_DER;
const unsigned char mbedtls_test_ca_key_rsa_der[]  = TEST_CA_KEY_RSA_DER;
const unsigned char mbedtls_test_ca_crt_rsa_sha1_der[]   =
    TEST_CA_CRT_RSA_SHA1_DER;
const unsigned char mbedtls_test_ca_crt_rsa_sha256_der[] =
    TEST_CA_CRT_RSA_SHA256_DER;

const size_t mbedtls_test_ca_crt_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_ca_crt_sphincs_shake256_pem);
const size_t mbedtls_test_ca_crt_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_ca_crt_sphincs_sha256_pem);
    
const size_t mbedtls_test_ca_crt_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_ca_crt_dilithium_shake256_pem);

const size_t mbedtls_test_ca_crt_ec_pem_len =
    sizeof( mbedtls_test_ca_crt_ec_pem );
const size_t mbedtls_test_ca_key_ec_pem_len =
    sizeof( mbedtls_test_ca_key_ec_pem );
const size_t mbedtls_test_ca_pwd_ec_pem_len =
    sizeof( mbedtls_test_ca_pwd_ec_pem ) - 1;
const size_t mbedtls_test_ca_key_rsa_pem_len =
    sizeof( mbedtls_test_ca_key_rsa_pem );
const size_t mbedtls_test_ca_pwd_rsa_pem_len =
    sizeof( mbedtls_test_ca_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_ca_crt_rsa_sha1_pem_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1_pem );
const size_t mbedtls_test_ca_crt_rsa_sha256_pem_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256_pem );

const size_t mbedtls_test_ca_crt_ec_der_len =
    sizeof( mbedtls_test_ca_crt_ec_der );
const size_t mbedtls_test_ca_key_ec_der_len =
    sizeof( mbedtls_test_ca_key_ec_der );
const size_t mbedtls_test_ca_pwd_ec_der_len = 0;
const size_t mbedtls_test_ca_key_rsa_der_len =
    sizeof( mbedtls_test_ca_key_rsa_der );
const size_t mbedtls_test_ca_pwd_rsa_der_len = 0;
const size_t mbedtls_test_ca_crt_rsa_sha1_der_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1_der );
const size_t mbedtls_test_ca_crt_rsa_sha256_der_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256_der );

/*
 * Server
 */

const char mbedtls_test_srv_crt_sphincs_shake256_pem[] = TEST_SRV_CRT_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_srv_crt_sphincs_sha256_pem[] = TEST_SRV_CRT_SPHINCS_SHA256_PEM;
const char mbedtls_test_srv_key_sphincs_shake256_pem[] = TEST_SRV_KEY_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_srv_key_sphincs_sha256_pem[] = TEST_SRV_KEY_SPHINCS_SHA256_PEM;

const char mbedtls_test_srv_crt_dilithium_shake256_pem[] = TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM;
const char mbedtls_test_srv_key_dilithium_shake256_pem[] = TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM;

const char mbedtls_test_srv_crt_ec_pem[]           = TEST_SRV_CRT_EC_PEM;
const char mbedtls_test_srv_key_ec_pem[]           = TEST_SRV_KEY_EC_PEM;
const char mbedtls_test_srv_pwd_ec_pem[]           = "";
const char mbedtls_test_srv_key_rsa_pem[]          = TEST_SRV_KEY_RSA_PEM;
const char mbedtls_test_srv_pwd_rsa_pem[]          = "";
const char mbedtls_test_srv_crt_rsa_sha1_pem[]     = TEST_SRV_CRT_RSA_SHA1_PEM;
const char mbedtls_test_srv_crt_rsa_sha256_pem[]   = TEST_SRV_CRT_RSA_SHA256_PEM;

const unsigned char mbedtls_test_srv_crt_ec_der[]   = TEST_SRV_CRT_EC_DER;
const unsigned char mbedtls_test_srv_key_ec_der[]   = TEST_SRV_KEY_EC_DER;
const unsigned char mbedtls_test_srv_key_rsa_der[]  = TEST_SRV_KEY_RSA_DER;
const unsigned char mbedtls_test_srv_crt_rsa_sha1_der[]   =
    TEST_SRV_CRT_RSA_SHA1_DER;
const unsigned char mbedtls_test_srv_crt_rsa_sha256_der[] =
    TEST_SRV_CRT_RSA_SHA256_DER;

const size_t mbedtls_test_srv_crt_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_srv_crt_sphincs_shake256_pem);
const size_t mbedtls_test_srv_crt_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_srv_crt_sphincs_sha256_pem);
const size_t mbedtls_test_srv_key_sphincs_shake256_pem_len =
    sizeof(mbedtls_test_srv_key_sphincs_shake256_pem);
const size_t mbedtls_test_srv_key_sphincs_sha256_pem_len =
    sizeof(mbedtls_test_srv_key_sphincs_sha256_pem);
    
const size_t mbedtls_test_srv_crt_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_srv_crt_dilithium_shake256_pem);
const size_t mbedtls_test_srv_key_dilithium_shake256_pem_len =
    sizeof(mbedtls_test_srv_key_dilithium_shake256_pem);

const size_t mbedtls_test_srv_crt_ec_pem_len =
    sizeof( mbedtls_test_srv_crt_ec_pem );
const size_t mbedtls_test_srv_key_ec_pem_len =
    sizeof( mbedtls_test_srv_key_ec_pem );
const size_t mbedtls_test_srv_pwd_ec_pem_len =
    sizeof( mbedtls_test_srv_pwd_ec_pem ) - 1;
const size_t mbedtls_test_srv_key_rsa_pem_len =
    sizeof( mbedtls_test_srv_key_rsa_pem );
const size_t mbedtls_test_srv_pwd_rsa_pem_len =
    sizeof( mbedtls_test_srv_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_srv_crt_rsa_sha1_pem_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1_pem );
const size_t mbedtls_test_srv_crt_rsa_sha256_pem_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256_pem );

const size_t mbedtls_test_srv_crt_ec_der_len =
    sizeof( mbedtls_test_srv_crt_ec_der );
const size_t mbedtls_test_srv_key_ec_der_len =
    sizeof( mbedtls_test_srv_key_ec_der );
const size_t mbedtls_test_srv_pwd_ec_der_len = 0;
const size_t mbedtls_test_srv_key_rsa_der_len =
    sizeof( mbedtls_test_srv_key_rsa_der );
const size_t mbedtls_test_srv_pwd_rsa_der_len = 0;
const size_t mbedtls_test_srv_crt_rsa_sha1_der_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1_der );
const size_t mbedtls_test_srv_crt_rsa_sha256_der_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256_der );

/*
 * Client
 */

const char mbedtls_test_cli_crt_ec_pem[]   = TEST_CLI_CRT_EC_PEM;
const char mbedtls_test_cli_key_ec_pem[]   = TEST_CLI_KEY_EC_PEM;
const char mbedtls_test_cli_pwd_ec_pem[]   = "";
const char mbedtls_test_cli_key_rsa_pem[]  = TEST_CLI_KEY_RSA_PEM;
const char mbedtls_test_cli_pwd_rsa_pem[]  = "";
const char mbedtls_test_cli_crt_rsa_pem[]  = TEST_CLI_CRT_RSA_PEM;

const unsigned char mbedtls_test_cli_crt_ec_der[]   = TEST_CLI_CRT_EC_DER;
const unsigned char mbedtls_test_cli_key_ec_der[]   = TEST_CLI_KEY_EC_DER;
const unsigned char mbedtls_test_cli_key_rsa_der[]  = TEST_CLI_KEY_RSA_DER;
const unsigned char mbedtls_test_cli_crt_rsa_der[]  = TEST_CLI_CRT_RSA_DER;

const size_t mbedtls_test_cli_crt_ec_pem_len =
    sizeof( mbedtls_test_cli_crt_ec_pem );
const size_t mbedtls_test_cli_key_ec_pem_len =
    sizeof( mbedtls_test_cli_key_ec_pem );
const size_t mbedtls_test_cli_pwd_ec_pem_len =
    sizeof( mbedtls_test_cli_pwd_ec_pem ) - 1;
const size_t mbedtls_test_cli_key_rsa_pem_len =
    sizeof( mbedtls_test_cli_key_rsa_pem );
const size_t mbedtls_test_cli_pwd_rsa_pem_len =
    sizeof( mbedtls_test_cli_pwd_rsa_pem ) - 1;
const size_t mbedtls_test_cli_crt_rsa_pem_len =
    sizeof( mbedtls_test_cli_crt_rsa_pem );

const size_t mbedtls_test_cli_crt_ec_der_len =
    sizeof( mbedtls_test_cli_crt_ec_der );
const size_t mbedtls_test_cli_key_ec_der_len =
    sizeof( mbedtls_test_cli_key_ec_der );
const size_t mbedtls_test_cli_key_rsa_der_len =
    sizeof( mbedtls_test_cli_key_rsa_der );
const size_t mbedtls_test_cli_crt_rsa_der_len =
    sizeof( mbedtls_test_cli_crt_rsa_der );

/*
 *
 * Definitions of test CRTs without specification of all parameters, choosing
 * them automatically according to the config. For example, mbedtls_test_ca_crt
 * is one of mbedtls_test_ca_crt_{rsa|ec}_{sha1|sha256}_{pem|der}.
 *
 */

/*
 * Dispatch between PEM and DER according to config
 */

#if defined(MBEDTLS_PEM_PARSE_C)

/* PEM encoded test CA certificates and keys */

#define TEST_CA_KEY_RSA                 TEST_CA_KEY_RSA_PEM
#define TEST_CA_PWD_RSA                 TEST_CA_PWD_RSA_PEM
#define TEST_CA_CRT_RSA_SHA256          TEST_CA_CRT_RSA_SHA256_PEM
#define TEST_CA_CRT_RSA_SHA1            TEST_CA_CRT_RSA_SHA1_PEM
#define TEST_CA_KEY_EC                  TEST_CA_KEY_EC_PEM
#define TEST_CA_PWD_EC                  TEST_CA_PWD_EC_PEM
#define TEST_CA_CRT_EC                  TEST_CA_CRT_EC_PEM
#define TEST_CA_CRT_SPHINCS_SHAKE256    TEST_CA_CRT_SPHINCS_SHAKE256_PEM
#define TEST_CA_CRT_SPHINCS_SHA256      TEST_CA_CRT_SPHINCS_SHA256_PEM
#define TEST_CA_CRT_DILITHIUM_SHAKE256  TEST_CA_CRT_DILITHIUM_SHAKE256_PEM

/* PEM encoded test server certificates and keys */

#define TEST_SRV_KEY_RSA        TEST_SRV_KEY_RSA_PEM
#define TEST_SRV_PWD_RSA        ""
#define TEST_SRV_CRT_RSA_SHA256 TEST_SRV_CRT_RSA_SHA256_PEM
#define TEST_SRV_CRT_RSA_SHA1   TEST_SRV_CRT_RSA_SHA1_PEM
#define TEST_SRV_KEY_EC         TEST_SRV_KEY_EC_PEM
#define TEST_SRV_PWD_EC         ""
#define TEST_SRV_CRT_EC         TEST_SRV_CRT_EC_PEM
#define TEST_SRV_CRT_SPHINCS_SHAKE256    TEST_SRV_CRT_SPHINCS_SHAKE256_PEM
#define TEST_SRV_CRT_SPHINCS_SHA256      TEST_SRV_CRT_SPHINCS_SHA256_PEM
#define TEST_SRV_KEY_SPHINCS_SHAKE256    TEST_SRV_KEY_SPHINCS_SHAKE256_PEM
#define TEST_SRV_KEY_SPHINCS_SHA256      TEST_SRV_KEY_SPHINCS_SHA256_PEM
#define TEST_SRV_CRT_DILITHIUM_SHAKE256    TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM
#define TEST_SRV_KEY_DILITHIUM_SHAKE256    TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM

/* PEM encoded test client certificates and keys */

#define TEST_CLI_KEY_RSA  TEST_CLI_KEY_RSA_PEM
#define TEST_CLI_PWD_RSA  ""
#define TEST_CLI_CRT_RSA  TEST_CLI_CRT_RSA_PEM
#define TEST_CLI_KEY_EC   TEST_CLI_KEY_EC_PEM
#define TEST_CLI_PWD_EC   ""
#define TEST_CLI_CRT_EC   TEST_CLI_CRT_EC_PEM


#else /* MBEDTLS_PEM_PARSE_C */

/* DER encoded test CA certificates and keys */

#define TEST_CA_KEY_RSA        TEST_CA_KEY_RSA_DER
#define TEST_CA_PWD_RSA        ""
#define TEST_CA_CRT_RSA_SHA256 TEST_CA_CRT_RSA_SHA256_DER
#define TEST_CA_CRT_RSA_SHA1   TEST_CA_CRT_RSA_SHA1_DER
#define TEST_CA_KEY_EC         TEST_CA_KEY_EC_DER
#define TEST_CA_PWD_EC         ""
#define TEST_CA_CRT_EC         TEST_CA_CRT_EC_DER
#define TEST_CA_CRT_SPHINCS_SHAKE256      ""
#define TEST_CA_CRT_SPHINCS_SHA256        ""
#define TEST_CA_CRT_DILITHIUM_SHAKE256    ""

/* DER encoded test server certificates and keys */

#define TEST_SRV_KEY_RSA        TEST_SRV_KEY_RSA_DER
#define TEST_SRV_PWD_RSA        ""
#define TEST_SRV_CRT_RSA_SHA256 TEST_SRV_CRT_RSA_SHA256_DER
#define TEST_SRV_CRT_RSA_SHA1   TEST_SRV_CRT_RSA_SHA1_DER
#define TEST_SRV_KEY_EC         TEST_SRV_KEY_EC_DER
#define TEST_SRV_PWD_EC         ""
#define TEST_SRV_CRT_EC         TEST_SRV_CRT_EC_DER
#define TEST_SRV_CRT_SPHINCS_SHAKE256      ""
#define TEST_SRV_CRT_SPHINCS_SHA256       ""
#define TEST_SRV_KEY_SPHINCS_SHAKE256     ""
#define TEST_SRV_KEY_SPHINCS_SHA256       ""
#define TEST_SRV_CRT_DILITHIUM_SHAKE256   ""
#define TEST_SRV_KEY_DILITHIUM_SHAKE256   ""

/* DER encoded test client certificates and keys */

#define TEST_CLI_KEY_RSA  TEST_CLI_KEY_RSA_DER
#define TEST_CLI_PWD_RSA  ""
#define TEST_CLI_CRT_RSA  TEST_CLI_CRT_RSA_DER
#define TEST_CLI_KEY_EC   TEST_CLI_KEY_EC_DER
#define TEST_CLI_PWD_EC   ""
#define TEST_CLI_CRT_EC   TEST_CLI_CRT_EC_DER

#endif /* MBEDTLS_PEM_PARSE_C */

const char mbedtls_test_ca_key_rsa[]         = TEST_CA_KEY_RSA;
const char mbedtls_test_ca_pwd_rsa[]         = TEST_CA_PWD_RSA;
const char mbedtls_test_ca_crt_rsa_sha256[]  = TEST_CA_CRT_RSA_SHA256;
const char mbedtls_test_ca_crt_rsa_sha1[]    = TEST_CA_CRT_RSA_SHA1;
const char mbedtls_test_ca_key_ec[]          = TEST_CA_KEY_EC;
const char mbedtls_test_ca_pwd_ec[]          = TEST_CA_PWD_EC;
const char mbedtls_test_ca_crt_ec[]          = TEST_CA_CRT_EC;
const char mbedtls_test_ca_crt_sphincs_shake256[] = TEST_CA_CRT_SPHINCS_SHAKE256;
const char mbedtls_test_ca_crt_sphincs_sha256[] = TEST_CA_CRT_SPHINCS_SHA256;
const char mbedtls_test_ca_crt_dilithium_shake256[] = TEST_CA_CRT_DILITHIUM_SHAKE256;

const char mbedtls_test_srv_key_rsa[]        = TEST_SRV_KEY_RSA;
const char mbedtls_test_srv_pwd_rsa[]        = TEST_SRV_PWD_RSA;
const char mbedtls_test_srv_crt_rsa_sha256[] = TEST_SRV_CRT_RSA_SHA256;
const char mbedtls_test_srv_crt_rsa_sha1[]   = TEST_SRV_CRT_RSA_SHA1;
const char mbedtls_test_srv_key_ec[]         = TEST_SRV_KEY_EC;
const char mbedtls_test_srv_pwd_ec[]         = TEST_SRV_PWD_EC;
const char mbedtls_test_srv_crt_ec[]         = TEST_SRV_CRT_EC;
const char mbedtls_test_srv_key_sphincs_shake256[] = TEST_SRV_KEY_SPHINCS_SHAKE256;
const char mbedtls_test_srv_key_sphincs_sha256[] = TEST_SRV_KEY_SPHINCS_SHA256;
const char mbedtls_test_srv_crt_sphincs_shake256[] = TEST_SRV_CRT_SPHINCS_SHAKE256;
const char mbedtls_test_srv_crt_sphincs_sha256[] = TEST_SRV_CRT_SPHINCS_SHA256;
const char mbedtls_test_srv_key_dilithium_shake256[] = TEST_SRV_KEY_DILITHIUM_SHAKE256;
const char mbedtls_test_srv_crt_dilithium_shake256[] = TEST_SRV_CRT_DILITHIUM_SHAKE256;

const char mbedtls_test_cli_key_rsa[]        = TEST_CLI_KEY_RSA;
const char mbedtls_test_cli_pwd_rsa[]        = TEST_CLI_PWD_RSA;
const char mbedtls_test_cli_crt_rsa[]        = TEST_CLI_CRT_RSA;
const char mbedtls_test_cli_key_ec[]         = TEST_CLI_KEY_EC;
const char mbedtls_test_cli_pwd_ec[]         = TEST_CLI_PWD_EC;
const char mbedtls_test_cli_crt_ec[]         = TEST_CLI_CRT_EC;

const size_t mbedtls_test_ca_crt_sphincs_shake256_len =
    sizeof(mbedtls_test_ca_crt_sphincs_shake256);
const size_t mbedtls_test_ca_crt_sphincs_sha256_len =
    sizeof(mbedtls_test_ca_crt_sphincs_sha256);
const size_t mbedtls_test_ca_crt_dilithium_shake256_len =
    sizeof(mbedtls_test_ca_crt_dilithium_shake256);
const size_t mbedtls_test_ca_key_rsa_len =
    sizeof( mbedtls_test_ca_key_rsa );
const size_t mbedtls_test_ca_pwd_rsa_len =
    sizeof( mbedtls_test_ca_pwd_rsa ) - 1;
const size_t mbedtls_test_ca_crt_rsa_sha256_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha256 );
const size_t mbedtls_test_ca_crt_rsa_sha1_len =
    sizeof( mbedtls_test_ca_crt_rsa_sha1 );
const size_t mbedtls_test_ca_key_ec_len =
    sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_ec_len =
    sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_ca_crt_ec_len =
    sizeof( mbedtls_test_ca_crt_ec );

const size_t mbedtls_test_srv_crt_sphics_shake256_len =
    sizeof(mbedtls_test_srv_crt_sphincs_shake256);
const size_t mbedtls_test_srv_crt_sphincs_sha256_len =
    sizeof(mbedtls_test_srv_crt_sphincs_sha256);
const size_t mbedtls_test_srv_key_sphincs_shake256_len =
    sizeof(mbedtls_test_srv_key_sphincs_shake256);
const size_t mbedtls_test_srv_key_sphincs_sha256_len =
    sizeof(mbedtls_test_srv_key_sphincs_sha256);
const size_t mbedtls_test_srv_crt_dilithium_shake256_len =
    sizeof(mbedtls_test_srv_crt_dilithium_shake256);
const size_t mbedtls_test_srv_key_dilithium_shake256_len =
    sizeof(mbedtls_test_srv_key_dilithium_shake256);
const size_t mbedtls_test_srv_key_rsa_len =
    sizeof( mbedtls_test_srv_key_rsa );
const size_t mbedtls_test_srv_pwd_rsa_len =
    sizeof( mbedtls_test_srv_pwd_rsa ) -1;
const size_t mbedtls_test_srv_crt_rsa_sha256_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha256 );
const size_t mbedtls_test_srv_crt_rsa_sha1_len =
    sizeof( mbedtls_test_srv_crt_rsa_sha1 );
const size_t mbedtls_test_srv_key_ec_len =
    sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_srv_pwd_ec_len =
    sizeof( mbedtls_test_srv_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_ec_len =
    sizeof( mbedtls_test_srv_crt_ec );

const size_t mbedtls_test_cli_key_rsa_len =
    sizeof( mbedtls_test_cli_key_rsa );
const size_t mbedtls_test_cli_pwd_rsa_len =
    sizeof( mbedtls_test_cli_pwd_rsa ) - 1;
const size_t mbedtls_test_cli_crt_rsa_len =
    sizeof( mbedtls_test_cli_crt_rsa );
const size_t mbedtls_test_cli_key_ec_len =
    sizeof( mbedtls_test_cli_key_ec );
const size_t mbedtls_test_cli_pwd_ec_len =
    sizeof( mbedtls_test_cli_pwd_ec ) - 1;
const size_t mbedtls_test_cli_crt_ec_len =
    sizeof( mbedtls_test_cli_crt_ec );

/*
 * Dispatch between SHAKE256 and SHA-256 for SPHINCS+
 */
#define MBEDTLS_TEST_SHAKE256
#if defined(MBEDTLS_TEST_SHAKE256)
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHAKE256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHAKE256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHAKE256
#else
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHA256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHA256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHA256
#endif // defined(MBEDTLS_TEST_SHAKE256)


#if defined(MBEDTLS_TEST_SHAKE256)
#define TEST_CA_CRT_DILITHIUM  TEST_CA_CRT_DILITHIUM_SHAKE256
#define TEST_SRV_CRT_DILITHIUM TEST_SRV_CRT_DILITHIUM_SHAKE256
#define TEST_SRV_KEY_DILITHIUM TEST_SRV_KEY_DILITHIUM_SHAKE256
#endif // defined(MBEDTLS_TEST_SHAKE256)

/*
 * Dispatch between SHA-1 and SHA-256
 */
#if defined(MBEDTLS_SHA256_C)
#define TEST_CA_CRT_RSA  TEST_CA_CRT_RSA_SHA256
#define TEST_SRV_CRT_RSA TEST_SRV_CRT_RSA_SHA256
#else
#define TEST_CA_CRT_RSA  TEST_CA_CRT_RSA_SHA1
#define TEST_SRV_CRT_RSA TEST_SRV_CRT_RSA_SHA1
#endif /* MBEDTLS_SHA256_C */

const char mbedtls_test_ca_crt_rsa[]  = TEST_CA_CRT_RSA;
const char mbedtls_test_srv_crt_rsa[] = TEST_SRV_CRT_RSA;

const size_t mbedtls_test_ca_crt_rsa_len =
    sizeof( mbedtls_test_ca_crt_rsa );
const size_t mbedtls_test_srv_crt_rsa_len =
    sizeof( mbedtls_test_srv_crt_rsa );

/*
 * Dispatch between RSA and EC
 */

#if defined(MBEDTLS_SPHINCS_C)

#define TEST_CA_KEY ""
#define TEST_CA_PWD ""
#define TEST_CA_CRT TEST_CA_CRT_SPHINCS

#define TEST_SRV_KEY TEST_SRV_KEY_SPHINCS
#define TEST_SRV_PWD ""
#define TEST_SRV_CRT TEST_SRV_CRT_SPHINCS

#define TEST_CLI_KEY ""
#define TEST_CLI_PWD ""
#define TEST_CLI_CRT ""

#elif defined(MBEDTLS_DILITHIUM_C)

#define TEST_CA_KEY ""
#define TEST_CA_PWD ""
#define TEST_CA_CRT TEST_CA_CRT_DILITHIUM

#define TEST_SRV_KEY TEST_SRV_KEY_DILITHIUM
#define TEST_SRV_PWD ""
#define TEST_SRV_CRT TEST_SRV_CRT_DILITHIUM

#define TEST_CLI_KEY ""
#define TEST_CLI_PWD ""
#define TEST_CLI_CRT ""

#elif defined(MBEDTLS_RSA_C)

#define TEST_CA_KEY TEST_CA_KEY_RSA
#define TEST_CA_PWD TEST_CA_PWD_RSA
#define TEST_CA_CRT TEST_CA_CRT_RSA

#define TEST_SRV_KEY TEST_SRV_KEY_RSA
#define TEST_SRV_PWD TEST_SRV_PWD_RSA
#define TEST_SRV_CRT TEST_SRV_CRT_RSA

#define TEST_CLI_KEY TEST_CLI_KEY_RSA
#define TEST_CLI_PWD TEST_CLI_PWD_RSA
#define TEST_CLI_CRT TEST_CLI_CRT_RSA

#else /* no RSA, so assume ECDSA */

#define TEST_CA_KEY TEST_CA_KEY_EC
#define TEST_CA_PWD TEST_CA_PWD_EC
#define TEST_CA_CRT TEST_CA_CRT_EC

#define TEST_SRV_KEY TEST_SRV_KEY_EC
#define TEST_SRV_PWD TEST_SRV_PWD_EC
#define TEST_SRV_CRT TEST_SRV_CRT_EC

#define TEST_CLI_KEY TEST_CLI_KEY_EC
#define TEST_CLI_PWD TEST_CLI_PWD_EC
#define TEST_CLI_CRT TEST_CLI_CRT_EC

#endif /* MBEDTLS_RSA_C */

/* API stability forces us to declare
 *   mbedtls_test_{ca|srv|cli}_{key|pwd|crt}
 * as pointers. */
static const char test_ca_key[] = TEST_CA_KEY;
static const char test_ca_pwd[] = TEST_CA_PWD;
static const char test_ca_crt[] = TEST_CA_CRT;

static const char test_srv_key[] = TEST_SRV_KEY;
static const char test_srv_pwd[] = TEST_SRV_PWD;
static const char test_srv_crt[] = TEST_SRV_CRT;

static const char test_cli_key[] = TEST_CLI_KEY;
static const char test_cli_pwd[] = TEST_CLI_PWD;
static const char test_cli_crt[] = TEST_CLI_CRT;

const char *mbedtls_test_ca_key = test_ca_key;
const char *mbedtls_test_ca_pwd = test_ca_pwd;
const char *mbedtls_test_ca_crt = test_ca_crt;

const char *mbedtls_test_srv_key = test_srv_key;
const char *mbedtls_test_srv_pwd = test_srv_pwd;
const char *mbedtls_test_srv_crt = test_srv_crt;

const char *mbedtls_test_cli_key = test_cli_key;
const char *mbedtls_test_cli_pwd = test_cli_pwd;
const char *mbedtls_test_cli_crt = test_cli_crt;

const size_t mbedtls_test_ca_key_len =
    sizeof( test_ca_key );
const size_t mbedtls_test_ca_pwd_len =
    sizeof( test_ca_pwd ) - 1;
const size_t mbedtls_test_ca_crt_len =
    sizeof( test_ca_crt );

const size_t mbedtls_test_srv_key_len =
    sizeof( test_srv_key );
const size_t mbedtls_test_srv_pwd_len =
    sizeof( test_srv_pwd ) - 1;
const size_t mbedtls_test_srv_crt_len =
    sizeof( test_srv_crt );

const size_t mbedtls_test_cli_key_len =
    sizeof( test_cli_key );
const size_t mbedtls_test_cli_pwd_len =
    sizeof( test_cli_pwd ) - 1;
const size_t mbedtls_test_cli_crt_len =
    sizeof( test_cli_crt );

/*
 *
 * Lists of certificates
 *
 */

/* List of CAs in PEM or DER, depending on config */
const char * mbedtls_test_cas[] = {
#if defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_TEST_SHAKE256)
    mbedtls_test_ca_crt_sphincs_shake256,
#else
    mbedtls_test_ca_crt_sphincs_sha256,
#endif
#endif /*MBEDTLS_SPHINCS_C*/
#if defined(MBEDTLS_DILITHIUM_C)
    mbedtls_test_ca_crt_dilithium_shake256,
#endif /*MBEDTLS_DILITHIUM_C*/
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    mbedtls_test_ca_crt_rsa_sha1,
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA256_C)
    mbedtls_test_ca_crt_rsa_sha256,
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha1 ),
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA256_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha256 ),
#endif
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};

/* List of all available CA certificates in DER format */
const unsigned char * mbedtls_test_cas_der[] = {
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_test_ca_crt_rsa_sha256_der,
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    mbedtls_test_ca_crt_rsa_sha1_der,
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec_der,
#endif /* MBEDTLS_ECDSA_C */
    NULL
};

const size_t mbedtls_test_cas_der_len[] = {
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha256_der ),
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    sizeof( mbedtls_test_ca_crt_rsa_sha1_der ),
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec_der ),
#endif /* MBEDTLS_ECDSA_C */
    0
};

/* Concatenation of all available CA certificates in PEM format */
#if defined(MBEDTLS_PEM_PARSE_C)
const char mbedtls_test_cas_pem[] =
#if defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_TEST_SHAKE256)
    TEST_CA_CRT_SPHINCS_SHAKE256_PEM
#else
    TEST_CA_CRT_SPHINCS_SHA256_PEM
#endif // defined(MBEDTLS_TEST_SHAKE256)
#endif // defined(MBEDTLS_SPHINCS_C)
#if defined(MBEDTLS_DILITHIUM_C)
    TEST_CA_CRT_DILITHIUM_SHAKE256_PEM
#endif // defined(MBEDTLS_DILITHIUM_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA256_C)
    TEST_CA_CRT_RSA_SHA256_PEM
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA1_C)
    TEST_CA_CRT_RSA_SHA1_PEM
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    TEST_CA_CRT_EC_PEM
#endif /* MBEDTLS_ECDSA_C */
    "";
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif /* MBEDTLS_PEM_PARSE_C */

#endif /* MBEDTLS_CERTS_C */
