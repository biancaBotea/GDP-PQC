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
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIICBDCCAYigAwIBAgIJAMFD4n5iQ8zoMAwGCCqGSM49BAMCBQAwPjELMAkGA1UE\r\n" \
    "BhMCTkwxETAPBgNVBAoMCFBvbGFyU1NMMRwwGgYDVQQDDBNQb2xhcnNzbCBUZXN0\r\n" \
    "IEVDIENBMB4XDTE5MDIxMDE0NDQwMFoXDTI5MDIxMDE0NDQwMFowPjELMAkGA1UE\r\n" \
    "BhMCTkwxETAPBgNVBAoMCFBvbGFyU1NMMRwwGgYDVQQDDBNQb2xhcnNzbCBUZXN0\r\n" \
    "IEVDIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEw9orNEE3WC+HVv78ibopQ0tO\r\n" \
    "4G7DDldTMzlY1FK0kZU5CyPfXxckYkj8GpUpziwth8KIUoCv1mqrId240xxuWLjK\r\n" \
    "6LJpjvNBrSnDtF91p0dv1RkpVWmaUzsgtGYWYDMeo1AwTjAMBgNVHRMEBTADAQH/\r\n" \
    "MB0GA1UdDgQWBBSdbSAkSQE/K8t4tRm8fiTJ2/s2fDAfBgNVHSMEGDAWgBSdbSAk\r\n" \
    "SQE/K8t4tRm8fiTJ2/s2fDAMBggqhkjOPQQDAgUAA2gAMGUCMFHKrjAPpHB0BN1a\r\n" \
    "LH8TwcJ3vh0AxeKZj30mRdOKBmg/jLS3rU3g8VQBHpn8sOTTBwIxANxPO5AerimZ\r\n" \
    "hCjMe0d4CTHf1gFZMF70+IqEP+o5VHsIp2Cqvflb0VGWFC5l9a4cQg==\r\n"         \
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
    "-----BEGIN CERTIFICATE-----\r\n"                                      \
    "MIICHzCCAaWgAwIBAgIBCTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0EwHhcN\r\n" \
    "MTMwOTI0MTU1MjA0WhcNMjMwOTIyMTU1MjA0WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n" \
    "A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG\r\n" \
    "CCqGSM49AwEHA0IABDfMVtl2CR5acj7HWS3/IG7ufPkGkXTQrRS192giWWKSTuUA\r\n" \
    "2CMR/+ov0jRdXRa9iojCa3cNVc2KKg76Aci07f+jgZ0wgZowCQYDVR0TBAIwADAd\r\n" \
    "BgNVHQ4EFgQUUGGlj9QH2deCAQzlZX+MY0anE74wbgYDVR0jBGcwZYAUnW0gJEkB\r\n" \
    "PyvLeLUZvH4kydv7NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xh\r\n" \
    "clNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAoG\r\n" \
    "CCqGSM49BAMCA2gAMGUCMQCaLFzXptui5WQN8LlO3ddh1hMxx6tzgLvT03MTVK2S\r\n" \
    "C12r0Lz3ri/moSEpNZWqPjkCMCE2f53GXcYLqyfyJR078c/xNSUU5+Xxl7VZ414V\r\n" \
    "fGa5kHvHARBPc8YAIVIqDvHH1Q==\r\n"                                     \
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
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAEN8xW2XYJHlpyPsdZLf8gbu58+QaRdNCtFLX3aCJZYpJO5QDYIxH/\r\n" \
    "6i/SNF1dFr2KiMJrdw1VzYoqDvoByLTt/w==\r\n"                             \
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
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"ME4EEQDG5BB4AGmqi2XRbQiBgXBvBBEA/OWV1HvGDxoZWaVt1++vagQQMz3UPtyX\r\n"	\
"IvReqMChXREijwQRAOg1f5o9I1uY7sg9hoohdCQCAQo=\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN CERTIFICATE-----\r\n"	\
"MIJDrDCCASWgAwIBAgIBATAMBggqhkjOPQQD/wUAMCwxCzAJBgNVBAMMAkNBMRAw\r\n"	\
"DgYDVQQKDAdTUEhJTkNTMQswCQYDVQQGEwJERTAeFw0wMTAxMDEwMDAwMDBaFw0z\r\n"	\
"MDEyMzEyMzU5NTlaMDMxEjAQBgNVBAMMCWxvY2FsaG9zdDEQMA4GA1UECgwHU1BI\r\n"	\
"SU5DUzELMAkGA1UEBhMCREUwOzALBgcqhkjOPf8BBQADLAAwKQQRAMbkEHgAaaqL\r\n"	\
"ZdFtCIGBcG8EEQD85ZXUe8YPGhlZpW3X769qAgEKo00wSzAJBgNVHRMEAjAAMB0G\r\n"	\
"A1UdDgQWBBS40hOfJ63Tm/vnA2Kf8IINnjlhvDAfBgNVHSMEGDAWgBQ78jpUzv7H\r\n"	\
"e+usI8d/+OXSJFHmRDAMBggqhkjOPQQD/wUAA4JCcQC59ftH4bCSSHPNa9KDi6uL\r\n"	\
"SgRmtewG3jG6IqPGNT9DrLueTEqySQtPQdRhZKPZQegl99lqjbaxk/ILURBJdOj1\r\n"	\
"ntL2r/3amOHZC9JZ0KTsPhfylmq+Rvgzp1gECjA4zqu6mLZunWK/RifYDxNTy+MF\r\n"	\
"mpm5GJT2Fn8V7/6Q08AIv2/lEAArL7+F5htxSj/bg97Hqd0Wu+1FMYPXp/DRhmnb\r\n"	\
"+8McOunt2wr6sD9kX+WYeSQppwx88PkOclQ6yygGPuQPyg0sXLEavJzjDUGvWPdf\r\n"	\
"sZIZM5f1Gsn5qcgmAP2JXN40eYtNhCHG0zQ5Sxy6LKt2q0XE06a/vcI64ZXx1IZ3\r\n"	\
"FZfo7BYYnTpPw+Y01Kw/w6Z5D7sq8/jmHMYDwAoObY3L/m8vMOBpgbMucmjoV7Z8\r\n"	\
"i+Z8icBHPU+w5bTUCgWQqYvSy0pEkc1k6iv4jZFckdAU7fCqYUooahQcCGXsS8FH\r\n"	\
"J1b8qCzLCVMXlByRBURE5GZ04oKcDkll9kuDqMfpiewIX0zUscEzRrI64R9sk1kP\r\n"	\
"pzscj9rAGGP6aPIINKz4QTByXq7LYTF3XANsvaRmc7IOqoTXjsfAG+VEo8rPRzSo\r\n"	\
"xvXGc4YrT4UGhtv9Zzlp38r4PhcIXEdY7t2+glT1UB2rKxZ1ncWccKD1ORjpkUmD\r\n"	\
"HDw2nH2UbqJxpemiLzVO13Nvb19KSOG7DoPBC+N/IxEe8mmmPtlScWlJw8Wfe9kw\r\n"	\
"EzSUPvayZiv8NrV44n5X0dk3XDRR+IrYdHHEHOLOD6tvHUSrmxSXPo9z5dlW1SGN\r\n"	\
"aRVQuA0e1KRFYppKLmLaxSZN82sExeSeq0WnFl7No6ebxaJ9adQJvQG96NLV41v+\r\n"	\
"mpoSHJozOVNw+QOwFKoV3AEQpA0Xjno1R5WNAzlhaq2km/Whb10K0QLM449lOTKj\r\n"	\
"RQ5eeqK9BmUt6hzyCQMoGhIFCASHoja1cb7HSlODKgox/aolo/q05tuqtZZqySPc\r\n"	\
"F98o5P7/zZAG2PwoayAMRNs9x0MfInnrUgn3F/eK/oy+BidvwYoDXxs/ib6R98FC\r\n"	\
"kpthVRFRRAhNL+dkNivZnff6+9gUwPpRhi5yLsyslnsrpIz1Ybh1WY6tjBYI53b7\r\n"	\
"SxuSNOpmnXJTau251sap2dTYsa4q0Q+3mgzKaEMcDfP5g+FrnPtzXKB9c754+lij\r\n"	\
"iqT6CI/PwttWYngtC9NAqX49XE4X+MlgCQQrpWA8jdJqOtCD3fVMPd86lFUOXyZT\r\n"	\
"1V6ve4z2JElbQ3BR/krIlNZqANtLq+PmUZ34lufBZf+azAJG2wZN8iQtp4JrCGOg\r\n"	\
"eCiNNnkCkC3uG8KTR8XQh4spXILfrSHXvgAPBMNHBhONBL3zUz7gtO5fuhO1IUhE\r\n"	\
"6WRQV0/4JNBWHeMlLE4jZyqUb/SL7ZvU1UK16OAs/KpzrlKJ2VravVmwUYTQYtGQ\r\n"	\
"XPDC171cHu2njIwYsvdDB+02cfDCDoQdEWEHuyifZ1NKv3vDKOu4i969mgec1jYS\r\n"	\
"XQuuMgwwqIgKmJDHPo7/82R68HDnV/Sdo0GjHn3JsB8iGdB06HqDiCJ8Oyh1Lgxe\r\n"	\
"b6c5zJ2TU8BA88szK+DtwaGvxX1XSkvda6C7wMmwV1F/e5acWE9slacJEiiqM60W\r\n"	\
"YLGmsKZ9DGEXhcRnypRT2fRTRelWP99Z0TyCt2yOm6FEU/jqU9kzPOkfwpUoavYy\r\n"	\
"ue0l+5h2MBf6p3LZAcAjLTI64Xd5G3J87n9WuRI9IGVdwDUG0ybaVFqdE1SjogZn\r\n"	\
"qgunbmv+8QxAiNfnux8fDpNaAA1K3h40ZTJyxqJCrTAyThaJvMwgqDO1RFEPHU2X\r\n"	\
"b+BjUZUKFUf3Ayp4fTD3UFE3hzONXEPUxmCTf77SExoR1CXXj43Xymel4eUIOyvO\r\n"	\
"XBDQyfz7y0JoOK6mfyZxfEt7s4h5jq1oQIgCU6F7FacY+glol0l8dNXHPXL17JWX\r\n"	\
"hNzww6Cg8fw2vGXJpLrYA6s86IN2KpgpAIECbv87bwTeYzF/aTuQy560dwua5If7\r\n"	\
"mrMQfIA2D0XySxcrDgQ42gYk/EXeEe1ACvJ/228jVfszF1cS/fyXJR5Z0KBn/ga7\r\n"	\
"oprJzhoGXoN7T3R0VDYJpGmEU1TddKgzUnTzGucHfWz6VAQ76y3905jhXeJ1XQWb\r\n"	\
"VcJMOKruD14g/nkYhjK/JeAP9sodueiCI9shyf5PxpMo56d5yOa0LYPH8WNV2mc5\r\n"	\
"KHtF5+MbKlA/iitIQAE49OlAeDbhAqLDHrMHuypf0OftQT7bk7qChcyh5G/RUAqy\r\n"	\
"2/1js9IYRxuVq7/2i3msEIFEuirFn58AW+zYijiwpQuC5YlTCaM8eMc1x2rhS0FS\r\n"	\
"OwzR1EnzOGr7SpZ2U8PatGF8gLpLSvU7glm4t/vT3rcGncZoG3q4R86nbiQs1VMl\r\n"	\
"PV07Q7vlFE6t5glv8EZkSbeP22uaEnfjSVGTr6U5/6M33mdeDJKKdKQ9Bta9IkcH\r\n"	\
"cteFg8gOIE4Rh8VKhC9I30s8whXDGeWdpAZgpeqFie6PuW1ZxjfBSrWqlqHH1QPW\r\n"	\
"KHsoY5+7GBu5dt/2XNXtPwMMOq9Fydak5f8nrHJywr7e8ZKqweHTRaBldze9+jBp\r\n"	\
"TM4EBimRLibALfkF7oY50eX8jCSH511MwMrj++zk9P6oLtyXrBlN9FOP44tZbBIW\r\n"	\
"4XZC71dYfdKfBDBeaWFElSABO1ai7VEwk7uCYJxTQHULrPt51pR6UmKrpj20fN4v\r\n"	\
"d15HdGv5g+koNlhf4Vn2lQdgXeIb9eE/Mc3rCV9+88RpH1OsV/Ul861nw3SC0tPZ\r\n"	\
"27vRBnkbCriglx7lBQIX6AuVXtaqHX9aFfkjM24BOYzRw0oVIVkeSo7atdv/5q64\r\n"	\
"x9oI5LreQ39EBbpKEXn4Vz4zvi76Tr0nhn5WzzuXnef5Ye5a9c7sbN1YkzU9Hx43\r\n"	\
"rGvrBLr5lUYl/ob36T/L8Vhj2bMvyHmoNbzEzgXLQDJKtfNZ+Z2Q7XMhC4cXx08f\r\n"	\
"+0rG5V5ruwM+NwsBl6TVhRrEEcIor8V7+mPJDUohDzcQsZtsfhCWhg+tLJEohdqB\r\n"	\
"VLkHjZJzUvuN0JE9zF0z5BYHaeurb6zGAmz0JgBq5NCepam8UbdFbbyU4XAUIkBm\r\n"	\
"Woq0aUpjKwjWm/H9r8zwqiVQKJBN3d1aZdZD0EM6jdoYMAUPnwkcQF30uNIHWAMF\r\n"	\
"MW2xCfa8XqwK144Qm+BzIlS0RajKIhD1FeG7KkJOCXwWsaaakSmUPd38mi9vVvq7\r\n"	\
"H6+owJ1y61CA7+njGvdhn+TGv7zndxQUqIm/Vi934RUiR0jeloVeXO7o3lvMuQrW\r\n"	\
"sUxQfT9XtgHTPFnZRVGW8pF/0MCcKIormzinBqhIciGCMWw42/Y1U8YX2fH8EWWw\r\n"	\
"omb1bbwplYR/4bkuCviPt9k6JBEya5w3QMhw226T/fVnQHXlhNGz4OfiGnHp0v+n\r\n"	\
"vEce9ePlJchG2rdxAQdWwFZ1u2Nh6Aj1lpCdB4w2azThztkKGJ5Jx97mGTDphSGY\r\n"	\
"Sw2Mw4h/PB7cnF6Bm1/BVcJo7JZAHFwBLOq6ozn83iXp1e3wnmCFWrysjPkCl3sS\r\n"	\
"1RN4F0hEMihvTQU2k8FYlkIW0WQLrhKc6S+lSqZoLKWPR+J8EGnFmraFe3b1ePbV\r\n"	\
"KrJQ2R4kLLq3ynszruwmr0AQx8YM7pn9UP8dppqBTw2H5kcWGWz2nKH9NA68NDHo\r\n"	\
"gR1y7OJAK10LmhsM2IMOIqz4RnlhZhTXU1LeafEDCM2rT+pl/xGEZP4r0DQJVW7o\r\n"	\
"My8EFQQrvAttkqVoD7u8OjNZvwAy2DXlYEXH7iUsEDGDRDHp9NELrhXkslb6AG1J\r\n"	\
"fUbKBuii4UCb/X4myQxFOiz9N6kU/wOy4DdfWsRaaUke0/VURpq2p5CdI8kcYL2P\r\n"	\
"0WoIbxg9qTT6+FjebvcAqUAM4Vos2aGxnONAMCSHhaIZdUf8Bzn/zyd0/reXiNy5\r\n"	\
"Os1YqrgefnF5Mb5LVOBen8SR1h78OYYnSQKZxKj44XNgCYX1dQCGobiYtdLt7DSZ\r\n"	\
"2f34vW2cNT61GWAQhgWhY7UzDQU/owB5sTPqYmH+bcObdzGaYdr81exHX1uiIF7l\r\n"	\
"bi9WtaXtO0jxn7kwjPC6QY0l/Wc7TLyTaiUFdUPg/F+B7K0cWJ3+kIxPd66VDZJ/\r\n"	\
"jDZ8kN+rmARKUHCTS+WKbLp77cURfl94NOu2NWGgZIfSuqYUZfESfAPVNRmLlOYB\r\n"	\
"ZBSsvqg38vc5JpCULWv7fjRJBplnRetr2ldkgl5tkYCVeB7rw3nf8zHUDxC7nH03\r\n"	\
"tBCknhc4EsWDPD3yhttgkEuA1T0kh8RMa5TLaGmgRnbMrMngGvytbS02VMei83qq\r\n"	\
"cCQTDMCI9LR1mJ/m72V1x8DmtnPzAKzUWaFLqJIKLgq8ZfZdKnERvPSfoRJXDRTq\r\n"	\
"9yFSWHcDBIn8s+wBb2jwqfCia5BxjBUGLZmiEnGylvm3o0j/BHymNnmIENsc6RKz\r\n"	\
"f+O5J2ECf/xwfoBS7E7g47RtIUwPAzOvP5rHEbwzbTqy1Hbu/Dx44qmNhGjQxn74\r\n"	\
"MEu5f5YijrN3gmbRiFSq8VPnBcKHAu1Pop6KKjdLkYnhRFEFP+f13Dyiwm3QqW/T\r\n"	\
"ik+AIkg5zSSYlYpFlEZeVmVcZ1Cu9k9BZwElZmleJSzO47ge/+1tXMhhUzPbTg2D\r\n"	\
"QLkBE3pFRxXpZqi4Txhb5mlM0C9WDlleyYbxJZpy/0VwNpGiAxwOskhRJbRzhwrZ\r\n"	\
"j6ovkTCpZJPkIEM8PQJtlX51KfpDvU53mBpaq1njn+7SpePcVNFDaBDDIkQj9olE\r\n"	\
"YALv36h+tVe/7lzPXU2zXFnQ45J0LbiC7QOYKs/QlOy3svmXcINqnEp+HcQTL/tK\r\n"	\
"OrEsmk/xQCV4CM6H5H2chLyqRZqr3lth6JkobzuYr5CTD3JgMg0HfGR0fOQgj2lJ\r\n"	\
"yakAp97EmM2nCJcGOnlFVQLeHIx2oT1X19WprcO2T9R9ESXzKAO+JgG+qkUA6tcd\r\n"	\
"6RddueXTb9PbAU69gubQucr9NnVZdFtxARyo72GMxIhLEQlz6bGYwjh02iyPle+p\r\n"	\
"0y9Dgj9Rv4JPeXXNscbrBjei2C45dfP3H2hs2mPfHI8p2HMEcQHq8RJIsaL8NJtv\r\n"	\
"gh3eq97EiKsgfLsv9S3DwPr25rSMLCD6baC8/uZixVNXURdA+CmA4GPM5GYycbyE\r\n"	\
"r111MzgCzU34RVWC22zR/8dP00ZLve+vk1FNootsxmD0nK8r+OJTHEAH1ntmM00f\r\n"	\
"7oBawZ5toGASr+m4E4D4Z1R4Ak0CbM0J8uuaMOGczKaDFaMbcjLFyqcVS82Kde29\r\n"	\
"5VUWlNFgsiuH6BW4wwnMkNiP8XrCR+PWCk5Et8UVEWJ4sMIZnDCs4TwmcpRS/HSr\r\n"	\
"d5hZJUCacQKiwojmB0How+WAuxOqIrreT9hYWLRcJSPVv4FoIEjBOEjUap4WbqKi\r\n"	\
"P3UqT8ucAKOzP20ojIXeoDjXXZPfuhqtExjay2nZJwfMjUxCu/le1oZm8jLxiUd3\r\n"	\
"ZEKyMJ484vzK8WG2qNcfyRwzpLKh2Q2N0xvC7vTWOb/DlVfG7P+g1Y8tNS5fvTC8\r\n"	\
"Gzg0hJzMt4qekIlLNGrgLJOqdm5oLpZ3RT9Nya1jOoumUV8k/Y9bulDUKG3UtWFG\r\n"	\
"eKpdHROxyDUK1nEcoCyCm+jgeHvczUDoj4wdqQIGwQLv0oc5jqlOB0mOJB8ceE9X\r\n"	\
"GSaV6y7bTVxFDbh3J9iI8+Gj5NTN2KoxLlRqjf4eBoR1RUZzTNyhcZGmbBa/TmLk\r\n"	\
"CirAblSrmr0J72FHCeW2KKnihQwuh99KZztUuuBUjzPNDSVCQ0g3Z5arbL2ZHtNB\r\n"	\
"2mQt8FJTv3D1foL8LCCWE/N66OO3vKF2LXND/E0wO0zADSO70jmaPUNc+TBbjKmT\r\n"	\
"EMyeU5dQY9PNAUxuhnLnBJrkKFbG4X7oNjegcJQCUVugo8XHQydct2H8h60c4Vj5\r\n"	\
"b9tcTlWQopo7uLyiOWJ2sYYtdhrwA+KwYYQpMAzIKfo7qpnmzXI7yrnfJWj7HlpL\r\n"	\
"IeIfEAHCGzL89EdFrTZqOMpcMfl2gCdFyU+uIBWXOpwSi+qAnWCLzgxYSvltRPf+\r\n"	\
"E7iu2bDCojGrCKCgzBVQFVMjVmcEMsSGplCjK9ALrKCPm9bhyv4ywt8SkzGJbmop\r\n"	\
"1vJ6jiv0hqggI9qYm+uk/YSDhH0uoEtDcyMKrt6QbUw1AHjcZc60f1wtSL08c/KN\r\n"	\
"32qSyPv5Br3/hlgXIjwrShmPtqRS9DHB/vqPKj/c61lPAcT04qGp2UyRkBk5rjpO\r\n"	\
"iO3Mr7oblOA6/2IRoXiSuUlTNZcXeFSrBXn3WOLQl8nB/PPygQsQEjxTYNCyz4aD\r\n"	\
"RLYaAwnCn3lIVVDlVk1rFJZIJw2HXaa7WBestt+jQEm0oGkQ19Fdy7nIyjtn0pFc\r\n"	\
"+Yv3t+TEr4Ly/8sYr4g1MFYkhKjmQF6URBHcmbYngGpGHQByz+PWw3E/QnyPMk+7\r\n"	\
"GeeiNoO5qJ29OH2g7YjGAhl1JoRQrSBB65hVQHpRvAov3gEky6lB0JL4Wqe5BL88\r\n"	\
"G+KDQtTZCpouwiYj8ca46QQixPDOFiTtxmuQBTqkZrrbIUnsMqTchf5bxd+n7Bjb\r\n"	\
"0Mi2EA9wf6aS5ft/bby9AOZEHCocxgy1wdZvH89zU3urnyqHFA/3dj8uiWFVjY3B\r\n"	\
"Oq1mXQycUpeQsf3aCjEW54YM2bJ8oYFFQxA4PigIlQ0wbnAnz7ZPKU8x+XSHpRFd\r\n"	\
"XreMgR9cX0lGYIAMYWEcDGzF2Y1w27K2nDugThGpYhIZADxDrSqb5yyr/6wlvSgy\r\n"	\
"X3h8Z2vgGL/9Ywe9+PQijZawK8tQFx5ssbBKukH2x7C8IXJWFYK2iC4W4Aeq1RMx\r\n"	\
"zTwX4metcPlliAOiNjn2DNy5WDOhZoLsMgaZ46cAJiHvJCWbA3KjcBcb1jlcYjqc\r\n"	\
"aoCBtkv1Uz2/EyublEfXr3TvwAPq9TVysYe7PH+dOsSn3208m000QI9DfSW1U2Xm\r\n"	\
"tyKkCrfXARBygPa9TppEB+rkunC7hVFPK7xL8umSyuaTSs9rTXZX+PeN0wI3GzMA\r\n"	\
"+0NsrLEx/x3XaCQA5R7U+UbJH/xM0vlCMPPiRpGupligOnGo8jI4hSY6H8kaAoJw\r\n"	\
"5MiF+Orww2d4DH6+0ZEPuLLr0gida8dwCDjzxw3AW1GJMqzWWUHMEl06za5ANgco\r\n"	\
"azH9BLRpgbqFPCfToIGdLaVk0JUbHoyZTMoAAPDcGO8kCGis59LaVAt3qxuJefR4\r\n"	\
"Ha34Bu14A6tupkVih4XTj5IOrO50ER1l+K6i3M8dWP0ZGWkQomYSOv9YGDpGgZrQ\r\n"	\
"FmY0ZAay9qEwTFneqGR+K5ryYXXCTganA0JpQB6Gu6O2PhVPX8RG1hobD3EORfqA\r\n"	\
"4Tbyf78aAjo7lg131bOc9s91Si0YOANzLGfYy+qqrVJd8XagtknQKDBhyRf2kEQI\r\n"	\
"6RcZbow/bGROVz7SyaVvvkXClFwDa/i8cJKq1IEia6oIli0LkHTpIJyMJYbMxxZU\r\n"	\
"cgopjX9GUsFrfXNILKO9boYWiQZSb0PRSgNyFrg22h9niksqeiwnkTkDw7vhmCt9\r\n"	\
"Enfucw+c0Pp1DBeTq5mEFRgD73x2Tw7NmQ5K1u0ZmOTboTKsVoo8cz76/ehL/mG8\r\n"	\
"S31K5XzivAahXLNYy5o376AlJlTUScPFr2sIVGfGioC+Zdxnnn+i3dUuW4gFVel9\r\n"	\
"RzEtY/L8ooycJ0uHwZ9cVf2h3k3ER4MSFM9/Vb2CJbM7BK3v7/3wkr1Io4Jv4ncl\r\n"	\
"iMNRHcKKwX5wrjDYObwLcoS+aNT2kFUsVYAj9SV2ypWqG+OEYCqXcjn2Ow9j0xcQ\r\n"	\
"Q2LU4VPnuQV2hv4g5L2wSJB4S3942Fp/enZ2RiE4tlxzLt6EOHJhOIOq8Z9PBiV8\r\n"	\
"xCrqT/Tck8DdGVYqP6XjYKKPkPwVpi3Qi8FkUl4/kNDQJnZwlnoVTZUJsEq/D7vO\r\n"	\
"px3Bes8Mr7eNXqNDww4oMEyy9ik+LQ7G2au4u1exQPE9/BWdvE2CZsUhice5tRl3\r\n"	\
"LSfnDL7aaRmJLFHKGjlR8yDDksPb/zHmNiT7j/qk6tWaFRYNGjXCm4YqFz6OYfTU\r\n"	\
"9Yww8M91S/l96o6x1Rxox3nEfOOhjr7NMBvASoMXc728LyhJFc+cP2AouUqNeGcm\r\n"	\
"8ejvmOD93jysFEjB2KmpeMYfItlDfwEFb4aM6kWVwGHHdwRheyvFH8AUr2QucgZj\r\n"	\
"M4p6E/Ckn5tDtkovEMON8I+1pVIAnQjL22PSzea7WyTh5d4xBNEL1AVtaoomKIY1\r\n"	\
"0Ae19oLkpWl9gOZqHXGg3S06Lf9fmQ2CZNNZQbZ9STZ742STouBrKk0xkXVhkvgm\r\n"	\
"lWFSKl/+O1zZDP9eIwmn44vttxcku2COfFHgoX2cJL8CaQwzeqj8tJqysPLqtlf7\r\n"	\
"D5p2XPlCocGmhlPfnJYkyhGkGbNfOlaC/V4aBN1VBRb5XjgH1RHz/9dTyIEIOdq+\r\n"	\
"MVfYztQoa1j7kX7hAF1Aie8/0uY14Suen8rdcV+x5hc+RlBj36VqLIlkwgcseZIX\r\n"	\
"XukcD8UuK+DGmqebq3C3MqyILP1JIRduIGFIAlq8ZTwFeonABYYP6eG8zXijCZz2\r\n"	\
"/RG5IXkOZZKBF2b99jHHxwphYGRkNq8AP5C+uwXVw8lyx2AXs1vSATmJtJgSRUmj\r\n"	\
"xIfO/OlWBlJ1+Opr0iHiOnxjRCURRVKKGviCIgoYQ07EJ72HkEqP9TjYRDzaxyYp\r\n"	\
"NhO4ndZNsAPdpSmG/TTulRVRaBZppwRHL3KSaBi3Hx4vKCb+a0KsafDg2CLskief\r\n"	\
"psH7TpC6kHX7o384xpZlg6ChBCN9X/mLS4QeH4wqLKYTnqN+5aqJdOuuu8SHfK9W\r\n"	\
"VGkw2ZRtBscrgKvCyN37dJhimlpNCrVO1caYHNf6X45vyQ5Yo34qOKV4NdlJEHoq\r\n"	\
"23koIYdua3dRpGMCvkxr9a0qj+bxbs3tzqzs8N8SqPlPd6MDtV8zWyBhtqEPbaKI\r\n"	\
"/aMntB7eokD9lSsy9wUHbEFx0Dt629d/fA8mmFQkOmy1MK5C0tDYrnLyAlLIJM8z\r\n"	\
"48im9YJv6Jon1fs5QzzfROSIZHeJWhv/6BxfNenFA3QNxqmlCIOCVez/eRPJKp9W\r\n"	\
"Anft7XjkvSsBo00aMWolaetjSptkq48Q/wIkMQtXPI8kUs66gAlTbhXrWqdZhgQd\r\n"	\
"D5TILa/1k2XK5kQSiO/1lc8tSskucLf9eTMPbss64VToOutsXNffO3jQx1oPIJjY\r\n"	\
"PULOiCBNcqKdqot34vpj5eHti+fXDkDaIz3R4SMz4PHsn2Vz5weWWh7cvHvrOU5z\r\n"	\
"7iBrjlYiSRwV2Cm+NWEN4a1Ly7BaXh5qrO4a8bdLLsIL2Y/uIP3Gkc7oCMeMJqOM\r\n"	\
"xXxRDqTwoZ14I4vZY6HfV7kWJ8phu7478Xr0qzBVx7/7G8+/DH2KP6mjSJf+QY4P\r\n"	\
"z/UOLjr+2nkd41KUJJXZCuFEbj7GuC7Ubb5Yd+6oPj08aDn/NeqLjHBvkLQveI1o\r\n"	\
"9cQoFCIby5Bq0ONuzYbfdzhK/7QYTESQqKOBrnONLrSRp3hfkR3ABeRMH6glPt7j\r\n"	\
"eBXyyODAXwoBsYlgPh+xWOBM5ETymcpTk65O14j4uxVEV8MtfzdUvEle5HFYf/B4\r\n"	\
"H13fpKNtWBEE00swyo/qiVl5zu5IlFAfxzyShfEadzLnvow5cY9TfMNqB69DX5vg\r\n"	\
"trTZgp6cb8Cs2BO6ItiYExJr5aA9Ot8EALs76Z6Px9mZCogvmG3uiNvRjQmXNyVP\r\n"	\
"TSlWEnw7UdzNMPuw90fMRx/Trxi4m5L4vdPp8KOG0KMRAChCSHSj5nYnw5FoVnHI\r\n"	\
"+PaRFUoa6ifoOQDOz7WCQhsuFkEEd/wg9o1BkFy5BCKRTXjazIa5cw7BIRrFas2A\r\n"	\
"1D8Y5cy19uHrryltSPOuR2WoKPoUpqfX0Di4XPEqJbXkCyc7nRf8Clud+q/3mXmM\r\n"	\
"LeX5H5yHRLnUArjliaxWJIQfAMjsm1YKPhB9dzafQ6sTkF6fd4Qmm5Njlel+q5nH\r\n"	\
"KZ4U740VsVMWwjNYHoSj2yGtXSHosDeDlQdJSfSZMMp+YXH15CgWJbpyjxdlsLVT\r\n"	\
"az02XGfz02rGIIMI9enGaRB+EVIJw/HSga1hKIZ95dM2PY7dfkaSSAwYGXqpndIa\r\n"	\
"k8dGJFt/JC1EgkXZmYUVrJFQPt4nk3eNDpSLbNbTadCRiOXIGvn2qweUpz27rE0W\r\n"	\
"7F9eEPAICqcPvwDEm2XnMG1H7TaOrmKnqEnvXkiKV7BaQgQy14rNRVeU3cEAVncL\r\n"	\
"NqBKwsp/MWB37hjMc5bAVNPgzcWMiIDuLz7oPAUZWzdd2YZKhq7a7gP8sctrc1hP\r\n"	\
"/Db5VZSnhxp0riO1zVVfcBqlJAUY2TEW/01M1HmQMfwQQ2eNQQp6K48DanKWnTaN\r\n"	\
"nrsHAOPu+7YEAwqGb9rPhWGwSQbTbJlYLP2hwn9mAPB1NBznPdxH/AxSHlOpojcP\r\n"	\
"Bw7QnMdP7oxebK1b4w2jZ0OTOe9GQTEHcCx+Cjt+5ZDYDmVn6HvP/p4ra3SfU2Te\r\n"	\
"ZqkWbid4hiS1EPEUo2DuMuZDOKbfb/QIidt9lxWEBy60X66yZ+nsj8jlaQ1axQWa\r\n"	\
"ClEGrOv1CfDKkzlFjgpb3bTPP72Bqczd2Swr6gNH9+ZEe/1nb47al2ZDURlKVAzl\r\n"	\
"G1ppBSwp//OoGtDmILeCsnUrdswJH3Zi3IPqie19es0CpxmR70Hv/Wn6s38YkPZn\r\n"	\
"ZFvnddGwDZQ31ESf8vkhXvZlWjuc3XhQVWJfxoDWMrHegTdaRwG7VXa0HTupsm0g\r\n"	\
"Ojj+x5f2rOi13a5I8Qc6h7L2dfRH+tzoKttgWg6h5Ae1Q/54e55tGSMwqFfu4TB3\r\n"	\
"qricogkj/WziyfLg+JKmYP6Y59VTS5BTTiwl6/hLuW5lHl/hlilKkJXPltu+uiVu\r\n"	\
"/aOwLHBs2Ial4ub4ARyGelRKB5Zn/lvq8CH3I+liRDZM4i4aU2qJCVEMmLUD10Kb\r\n"	\
"6RjnjTBn58GY1lnc4d74IbNAVJqqQskHDQqmJ9A9irIwXWaOGA0+Ss0Kxauj0lv7\r\n"	\
"Y6qUCGxYmP6+eYSLtTDLYLyT887DdnUiIVIx6C/IpkcUDnUv/s8IdyrtFhIe0YiG\r\n"	\
"RXa56/u3gnadYizpbus25iRDlcy8HgvT/nnxdQoipoTy+PkhfLvtplhmfxqwERjL\r\n"	\
"hlUc8RRqLzlBu9QEHYLpnnU/D2AuqsW0/dyvPpzF5yN6SgxOyy4YGikQqt0D3cO3\r\n"	\
"BztByHtGnjknyRo49eyLUCamg7zQef4y/SBgeBd/Uh7eQYFLGSIojZvCOzQewjQB\r\n"	\
"iFX5VFFwS9ohnZBz821JT+RVr75DKovbrv+fOcizOLDBHG2gy8A6Jlh9rZmoeOAV\r\n"	\
"aB/j/9vmEweJ2bXQ3LY9BUjVILC2Kz+e0/UP6tWyz43sVzoKpBDoyJHLfDnZfVhv\r\n"	\
"u2Mce5lhINbqH6buigBynw3+WU+KEQCOKOabOhlKX+MNtf1eW5ynuQfrksJsfHpB\r\n"	\
"z//GZRVAvQBaD+mpWln/Htk2QoXbzPJo1ipyvJpGuZPxg0O0v5j4m1SxXZ6TVjqK\r\n"	\
"S7ejdgDaKLPPlzsGXwt0MDV9LkSTw75vA4i6zevC0Fbp+ilhBjZHrjN46Ikzmgex\r\n"	\
"Am2LRtcmxwn4IiOjLyTXfl8z0rLsHBmIN1FxpiBDo24lZ9A2zbhuZNxXRb7c6EQN\r\n"	\
"d+fAhF0HNYyqC6kOYkSY26d8NpwwKR/GNucgWjli+HI8IqMoBBawYHKwXZLpcwgl\r\n"	\
"ehQfuFQoJyAiA2lMPEougFZVNKs18GZnYJ/wJiw548kgQQyXVPIzq/GFHR6VxleI\r\n"	\
"ps6ChCv4u5PnR7ZaFB7Qco0CDKz1mQ0o6wT+6jODXgyI/XOEDlUm18SxxD9WlwlO\r\n"	\
"ivOhlsPFt/D148lahCcNgi9mzgr041QxYvbwkZv910JFrKrcpDP4Duwd6VywkUzv\r\n"	\
"ogD0e5VD87YZ5O4ZWPVlf5fXfrN05AuPfdlvrF8gvOxwoDsCJImIGR+QlGSlbDKP\r\n"	\
"jHCa18cBzhLKJczXEb8aLySnBJCAtK5n05rdd7lDcsMCwsl5/FcnRWyMMbbifxWh\r\n"	\
"ABGouoG91BH2M0TvZFozyYDM3sABsvUIHj19iDHTojfG3vUD1z0wmmu11+7owBgE\r\n"	\
"5Xlc1XhJLqxUsKZHtnf30bOYfkqzDt4FsrkSNaLs6U/eTFm9G8H5AfTufujpgr0l\r\n"	\
"croS962Vu8kVhdOeYrBN+hT7FWdA47v3u7L3hKZu/inwUxxGuHIM+jlQvVxw5Wqt\r\n"	\
"kesDjfIqp1JVW+Vb37McQTCH4z9loXmMOECT1IDP+lwO57W3R1VZnNOqZz5xuGFc\r\n"	\
"7FzxjWnwZcJr1PCFpUwMYyjD0OG4WdX+qf42gi6VPfpAz9rw6jLCMiksu8+KWzNl\r\n"	\
"E5IsC/+7iIyF/OA8CWGejwvBKMUDZ7xQMJQpz6mb09gZUBwdTB/AGr3BkMEMM2vi\r\n"	\
"bnnDU4xDf86tHkDsfBVItCIeWQ1BFUK/UXHgmdOwI/MW6K5AVikJGirASwPut65D\r\n"	\
"cndiOSuIa2vYSPZBygo+kKQ3j/vFd/+R//BwdBaxbrNgVQgt3xMDWvPeUBv5EDm6\r\n"	\
"z5fA0cp+rG/WYwdlUE8ljlroUw6NboMfrGOEamhE0sMMtg2EOvLo8QlnJUDsl4RF\r\n"	\
"O3mc6vJuGhTSBdeKG8hDsPdwhBaPhwAK330Hu3K69JjV8sBHYsnF1WnIlkTunfLQ\r\n"	\
"B7sfV5v5BwMEstzGvoIvDTtZ5ETlXKFFxUWyJTgPZpE0fcSwD2BRXExIScOA72Sg\r\n"	\
"zbhx/x9Iyym7D9QNhNNdHWsG6vyjoAPXR0vpxXSAdHFfvB0uUKUafX0Qs5Sleugs\r\n"	\
"ezYuKtsp76A2psjYJ04tLpuGOyAl9hKdNaMruw0pt+OejPV/jzD8PhyybWsBGcxt\r\n"	\
"zxb2sPJ8aQHkA27VCMS1jTJe3Rok5P8yhMA/RzxSsycWTv7GodOGmFa3UlejZfg/\r\n"	\
"FTvd6gufKzKfTRpZ3q8ebKiekZgJapFKbJUtXr5JA5/CdG6eUm0jERochJll6xzo\r\n"	\
"OPRXXhvujSUIzFdbKAQu94Ap56dvBduG1Wvoj9BJMi/UNavNzRiX+TDqjtScQACD\r\n"	\
"VkcDpQU3KydJ3FaoXqGplhW0ihnaj/H6suVvkWFNww/xjCshTeVQco3Y4jVm0vmP\r\n"	\
"pejawzUbAerkTZ65TYjbIguCigcPlo0ZZdwFgDCZWtfYHYqEouP5OutW/kzqWbHI\r\n"	\
"+hmew3qgE1YfK6kuuZfilRGzje3+cW1vwVZFWt+SlZN5sIuv6/3UpUPBCI9tdnsD\r\n"	\
"+R/9nKW5QQ9vz2NhABvYzSH1Dn9Z1BUapJt7wBdi1uEXFlocZRNqHd4AI5+K+LRI\r\n"	\
"vqGaY8+ridzxx/z1O2Ks1wknRAF5g5HldBnaXNCavZbyH3Lr1XlLAB2eA9h5Q/x5\r\n"	\
"4/YkmCo03FYt9cOXSiUaR8k/cTp/Rhdww8C5wB+BES7OBhQDbDlozhFbogU7epNn\r\n"	\
"3qQ/XTImtCP+QGDYTf6WHto6RMZMdENbau8WH6nOQhGfIW1h3jp8/ep1jc4U78bB\r\n"	\
"/eu/6tu/HKcVoNnxyaa/rHNJ8iLMLwDKwJhq8t4w+zHIqXnZbN/aWvrsA+IwBuol\r\n"	\
"n8RV9WWreOtV26LsItk2FV8+zJLmx6Tw2t3kdgqBUA2UgwlHBO6ZIrKinGhAjNUG\r\n"	\
"SI9CXfst9dC/eX0ZRG0Yy9XeCUfAMxrn5RJyR+NpVwuGE477IPapVgeVROeWTc3k\r\n"	\
"V7xosb1U9fVwwOv4pn+XlFiyaAUpwNlv9KgADikjOkkBp2K5Y7phDrf3atmlwz5z\r\n"	\
"1QnBmtrKBhC6mUMIissNde5ojpBHSzCVROp5vrWTWcbPiORjM2nqC9ypVgQPnOUX\r\n"	\
"l/HrHREL80LGoCi7UNEswYSJpFmozhXjXMLEJ/jrazALzfHvGgOWzSOQQ1bvyAXM\r\n"	\
"FrlH3tsCgrdBEQzginLkjKGHiYop7HF35LCaoCUvdU4N9ZLSTlbR/mnGv5cAUznc\r\n"	\
"F3R/lnhBRsve0r+xSd4W28WABCYTkoVpbf/AZr6m0mLJzHj5u9KH9rNDAsDeL8+/\r\n"	\
"LsNqDA3JUfNyUbqT/JbP+1g6Bb9LVzcN1+Fwg+4EixT2yU5mr82Mk+Lv5qkoWWvy\r\n"	\
"uAzyCR+WmCTAz4p/uVioIlhtcH17+Le4YPH1Kw2lqnsnRjpIQfouuMuAYYVaKUlg\r\n"	\
"Mk/pSsLiRqkfGbdW6VNhW2q7/R0dePo9CweeC5AAd22FMcQOBmzm0G0gcatU5TXs\r\n"	\
"YRs36TvBbQCJu0uPrGhBvBYZ7rjec585uD79TSh3qoNpdW9ScWmUInNob0mj3Quk\r\n"	\
"OIy08f4lpXqOQH3jM2SsFtms3NzcoZEzHwwbsV14PI8v9mEFxQPyudRDriUssc+F\r\n"	\
"YRzXJ/8H1hI/boRtrBVV3DMfNB4D6C6+nhhMZPf8QfkPQPOoik1trmsAYtm/k4Ih\r\n"	\
"e/+ZGYj9ivc4+C0oQQ4W441y7Q+4hAcRcAgB7DTzKxwfsxpE1EfBISzjtq54nwDx\r\n"	\
"2FAbgGB/yjfV16xHvazOEjAZvC5zgFAhFzCXGsyK50MH8S4FuIeMiSLS6960Br+k\r\n"	\
"OhBdeRqBhd579OaTIVs4JSornbWqFzvBadBj5gqLjX1rRGi8scHP95DyyMB5D3AO\r\n"	\
"0T8EuKh4JjF6G7Fbh3DXxsR8TVpCZ/b+IoWEa4u6D5IJCocU3sO9j6va1Wrt/NAs\r\n"	\
"3NfphsZr8vhCWf0GsiXA5SbHpUIM/E0F1hS9kVeRbes2ZdgbA89xNKkhtgD+wMcL\r\n"	\
"Y7TYdYP9PysvXYo/P9L9jkNHbm7SA2rTXpnAkopOt/7LY3JQJXp959IuAZGD744J\r\n"	\
"yxExiSrj97Dg1WvVcZFtti4zPsUkAC0C7f6VFEAhVpqyZBJDUkpZWoloELxYWr50\r\n"	\
"1pkM5xkTEv31kd6DAp+cBLIp01Xe2AN0/IdzD6JBTCjdok1mt+A75WY/HR/sf7G5\r\n"	\
"S/qWoNi9gXGdR4PbfX7lQWtmF962jr1nJ+9j9koSsmGEFQNoRAOwTdtbLvirM0DU\r\n"	\
"dnANRVF7ZVQvxT7a0LffsVMupEIjE6ruqwqPFdtrQR5Pahru47i8RMJbKANENmiS\r\n"	\
"cvQsz8X0brCWOFn7rOsHT3TIoEOZ1t+lKf7aopc94bIECr4ov36oqPHVAbRdTIYV\r\n"	\
"t7JwF8318d9sd3pQXx8ofNtG51Nr78gBvTNXJuVeajkc4zS/CL2S9CBh+PloaCnZ\r\n"	\
"PgDkWe2Y/BZMG0CCT7zHdH0KDZzRogPodXgrFn3KpOexHR9VtMgehZW2Gn9L+bJh\r\n"	\
"YPTTFI1gUQHgWqC3SPf0ALBTrCc02+Y12iQpskLOOivdTJ5IMHR956CI1YEW7dx3\r\n"	\
"GkFhijYhP1rk/g+lu/KMev995S34i4gkA88/8bWK1LTqLvsxXo9PrMjXVPDZ6lrn\r\n"	\
"HCRUXc/Vfau3jrJYd+05zFND3HEQ+acxXp3AIK8lwSJClLsyu2tmVnfWRy0pKhB5\r\n"	\
"QbxHuj3CTc/7tZ9FlCS/lO984UiGmOgHFZKTfSu00cvhMRdSa9a5xtZen6+t7OIw\r\n"	\
"qlAHI+AjqfrwxOBpVH6dTkCOjEFvPCv7z4fPDRpo6upjBn4b5aZHc9O5Rt867H0S\r\n"	\
"twPtStWZ5/BcuiiM7rRghKQnPrV0XczWv0XhPEEfM0JDVkcDNpDw0BiKCjc9WIpL\r\n"	\
"uV5rAKM42TTd4/+YQPRd6z/05Yyuuou/1rdgYrT7Xoh/qhN0FVSToUP2kQZVPWBo\r\n"	\
"dcVW+/aq0OB45LPki5e8G1ARygy/HSL36oDdUQb4S+vt8QmM55N25DUvCxzey7Yf\r\n"	\
"Xh2zAoRIV7C/epHQMB0n5kusOwypNiNFIE5Bhc3OyzsEiMJihuw5ic16Pv/6cOij\r\n"	\
"0easOsMijb41k4+SACEYJUmzoaKbu4N3RzcXLplDytNI3Y0cpABFzhNLD2ZIWtTO\r\n"	\
"PBLdr5pRtG3unq1QP4wiEWsnQNEO173DM5/jIK+1oXO6UVfILSK+CXY0eNJXAC3F\r\n"	\
"u1C1IyVOYMuYcaXEnGN/vCvPzlRktiZ2w/DwBxCJZFJCiaL6B1ytQvfc9RHVw8iy\r\n"	\
"zdXEPBHYj/GO7ahwP6VWGeAO2RyfyG/h2PxAsu/pF294dVvRpN7GUsiC4WW7xTkT\r\n"	\
"ij+zDnjuw+jMwzqizStIul65DGAyM6k4PfpsacEnbEdd3GjCqATJ6889XYDllwd5\r\n"	\
"1aipugE8Fvnj8yNNo4wIlsptgDOfe2MKfz9MCg4FaPoeCMMilePmhP9PN440IbHh\r\n"	\
"nsLHJuywaLMEiUXbeC8zDG0XZCSYY1DPSxfAtDjr4aOkccJYlXevO+c7g3jFwUNh\r\n"	\
"Yq6ATgJ/EuOVqHEsomQV8SuunAMQrqnDSv2K5E2VNIElWWRHcXkaCljxsXS6KTGF\r\n"	\
"bm4ZG/pa4G1Svf9BuGhhyKB39c2e6DClmYmxD4fC5PrsdAUH7QywTAEwGOWbW7sZ\r\n"	\
"qDRZHvy/veaEs/XioekKxcRv3p7EsO3WP9jjqVTznAOjGVbj2Z7ZUUPU1hajDjUc\r\n"	\
"+kMS840w9cEqluXCSGLFK569TfdwWj/h5RwHRsowAsYijdJYYMrDn4MkcVd/Rx13\r\n"	\
"MnP5gUmpfWdReWXj2cig7htySFhmT7QzxeCPw53xdgIfFLu3KxGYhlqR+FZ9dgH4\r\n"	\
"jNqrC/ZzTY4I2ZxsCldL4c6UizhWhRUonhBgfPQWE6xhbtlGU28RlY8U9CeI6kir\r\n"	\
"UwmMaJs9i6JmtRfrS5yStDbazNUbTZNjPaJUTeklcmAeVFlykS2fv0r8txg4mztY\r\n"	\
"f4/sJ+7FAboSmmhGWTXuJC/3B3kdWjvSiQgO6NvZotSY7U1e4OBVEI2SpAWxv09U\r\n"	\
"gjV2mdK2VAuacohgalGWF7foTxrAI/jPcRY+/6LojHXn2lEQu8V9DGWg4xAvCj1K\r\n"	\
"q7PnJ9t5ml6DXR/7NKK8oRGJchJR0WxTHKNNAv25OcWgFDn58mKSza1v3S1JA1Tn\r\n"	\
"mfLBkZClaS/+iPvpIRiYXR/exBog6Hvj9SKXuS6RcBtOYqOO/haKuKA1XgE3T/RT\r\n"	\
"ILK6xGeGO6rF2BsetcAbfglKqwGsjPDfHo69nDNbG/zeS/tQqBE2nNyorRKbJYpW\r\n"	\
"Qw4x3PH5l6RWm5PrukI9oIwy6vsTvQIt/SoMv4Wr85VR5jKNYhJ6yWYEME7uZj16\r\n"	\
"F1Fux0fHtgplXCZp/06nk73PRYfnr2xP2dgUbtdmQQvA3O6F+qx4nt85dZB7KVad\r\n"	\
"7fIDNcYtMFhs2VbGLx1TSK4ldsDrCPvc+Uht5fIp6YQw5zkAF9ej7BDKoUIUmFoZ\r\n"	\
"L1zuWvDg7pJr+t4yaIAHqVBJkBwFPJbsvdb9li5waJsH14720ztZ0pJRzqKzTfHj\r\n"	\
"uNrU07CZwQglWDndV1iRyHlAskwksM3sx6dSjKdqGOamXf7K0I3KgxPR3Guc8uH8\r\n"	\
"G63KqkOEg2IMKY0quRCT7kW0l47LPYkGjUxyrIuO97Mk9knqg57EpvDUlWb9287H\r\n"	\
"oZscQ4WG+jg+XfKoCveFEBIn2LJyg96AXSi7gyl7GUpk5pkJJmfqE1QlTHwiTAoI\r\n"	\
"/TSlI4w/FqRAmzZJPAvKRbb+miBxdQ6+vlmJyTzOpyfS/tpswhx9FFl/EbiET+MG\r\n"	\
"XX4ZjBqWlILSnRClU8AUOnWf76OLCoXRW+h1arEtCOPcI4icjZfPhhqMqL6BU0ct\r\n"	\
"LQx0wtvGBZ5u5JUf6FbAuFlj8kLyT7cUP0+AafHqiMjpKCAxFJnI/22dTCA+oZUe\r\n"	\
"oaNm4VhIkeLsynE/DE0xrl1yq0Hw7S8SKzSNLiIiyIjOFC0/cVdN2rLnchXegccL\r\n"	\
"nIf7czPytzvDmoBILgbcaLbLP3UPNtCKGOlGawBRAZ/cPTCasv1C2g8d8I5WH4DA\r\n"	\
"96ytg1zmKzPHyasKDIf0/oWh4+0jzK/V+N/URY0zCbderItnm97cwO2lrQsfQb8b\r\n"	\
"aznnIJfBP7v6cKjzutsxSkv+iJn8wJpVGtnhO1wVgZfKk+RjB7x/kkuCh5J681jS\r\n"	\
"oSKCIl40mqFMJQRQWaEz3wCA74lPjWsSQQhYdEs6OUvt2aTn2j/0ybcVWeUnK54i\r\n"	\
"uiAYEs+5/aDcSdPVo9EcayKruc5AEokVY8oY0lXmKpsBLwhLu5rl5VSZCsf4Rasx\r\n"	\
"njnAvvbjLvfqtOjAYBTq+tRLbwCSon0HAEM+HEyhizuoQRzzt1YEWed7V9EmUDnc\r\n"	\
"HjHsvaJtLmbx4wIzN8ahE/QhddKhuwJdXECi/XYcWY9h4G4IGtDnJExNIPa88tRI\r\n"	\
"XWN2f4K5rztcsq2h7iV+eJvEB3nPQ5oO1/DVC83+XnnK35KFSbKUVvEEYwpDJz37\r\n"	\
"oLbDk2yCjBz3uVzG5GcQPLsW/o4k2MslzqxXGL9QTr1HwROl2W5i/dwrSYX4rEO6\r\n"	\
"GtIMUy1Jqna5N1WwX5dIaIgaCGaMLEkXycd2KaJl6wmFwAe2TajJ44rgGmJjg37w\r\n"	\
"pjiJw5EQBaugPNrKRGQ0a32j7HYhqBeGygQ8iOjz5rwjVmTyQQwLkj+YDVoIfgk/\r\n"	\
"2rnecXTiYvYpFoBxhP3ACzPRLnlbDG5r1tGURsYhVFivxhVHFOMdyQ0g7uorwxVd\r\n"	\
"bAy5zasOjBjBPNea2RsghB+fW7/n4yJ2qWlOmg7oFSpvXj7iNGEcflkW5SVPcg/o\r\n"	\
"BgIQW+IaOJqw/w9GiNL7AcWODSsRdHz2wO1vX5F68iDcKN0Q2mbWf95RkGHl33iK\r\n"	\
"Ay07sffzU6fY4Oa6msnGcLp4IpTpA35k4UoOcJv1sjfuAfvYCgVcEhokpZ1IaO9I\r\n"	\
"vD1o6MgFsGUCkhCZRsMYZvdux5qpbpIgjoYcFCpUtAtBTwgUAk/N/nNpuJGEeE3m\r\n"	\
"MCrqzdbcAM5XOaiZ8LPpLInhToixh7jhsSDJmhFbsICnpGYU/4hgxw5Otqk1N5Nh\r\n"	\
"ykYtA7nAjHBHo1RMdxNiFPwpUHRmnhqhNnjJ5Bv0wT3PsqB8i2fhwn3l50m3cYCD\r\n"	\
"bxqSJh2pmAP6tkpI7V5lQ2I8Y+mqTPptOGjs+b8K2iSwEWMr8Dulxp7/dlgpJa5g\r\n"	\
"Z/FIz4p0O/kWEk49UPCQtgq83ircdg+DC41SM07ZgpmDgHFBwypLoslvcWaLOA5T\r\n"	\
"6Voc8Eyl/Dy+n3MEUTs8IcHmLlVrQQCzJEwk2THzd8eIww0grsokwTDoXU+umcs8\r\n"	\
"RtzsXIzCC8DrpYcbScrA+lriWCUP1CcoeryUG/K38sbwTfzlR+a0bnz0yZs77uMY\r\n"	\
"FFZmkZqXoBLwMnA6KeHN63461q77d9ix7neJYO07a6AZxKL2sj14mkhhX7RQaCrN\r\n"	\
"f1StPsGr54zHHi019L2yNeBOc9Ze6NAdjDdN9Mc44/G193nWPL2BY1p+hDPI5Ueo\r\n"	\
"W41GsDTt7l9Q66F1LVYfoAObc165FZli6sCdscH0X131VC8G2nAWGuMPdofSgr1f\r\n"	\
"syxrK9rSqZ9beaqyi+Sef0nn3862vKoMmWoBdG76iG+GX+SdsqVicmyKecnuJG21\r\n"	\
"su3SM2rBF+WNQuzg7+OQvli+G7cZKuh7J7FauQ5KjPwzxez5AItR7PSBhdWpUH8q\r\n"	\
"snuNVpI08JltSUyicXqp2CT9kP1mZ/2+wPllqom/eoaW7JIGG8yjvDW7o3Q0EK0/\r\n"	\
"lkznCOt/M/+T3JGb7OuPeN0xcWVWKhR0iIjeXKvze7l0d77PNEvGmhNE4rJGhwZT\r\n"	\
"6PQN4s2JNFAUkYnfAFrP9Q+R+HR89TUrrPW/wXpYJh4oIMS2Sf/LxN8xFw9/opSn\r\n"	\
"0QTZKUzGDGyH1/tKZJf5U1/08ygdOzWgYRmHRylSchiGG+8gUHzaihBK8SN5xoG5\r\n"	\
"hGy2MusdzQ/iU6q/ZYu9G0fSJ2K0Vw9y0TPADgOkkyezJMbRsI9VInSfVPceIajI\r\n"	\
"Nn7TO4u4BkB0xqlRCfoL0qKIb78SbadR5FTXYJHqQA9E57ERj7BkZkdhBPc1RBv9\r\n"	\
"6Dr0FHVxf4kR5hPVqldgyhykGj74thjm8Z4Z7tkviUAiOY0ASaKEUtnEwCPMpSmO\r\n"	\
"uCoUikeuH+r7V12Ig8UXrV1N3w6fpYwuzkYzlmBssqHVYZQqr2S9BgOifE5RBfD8\r\n"	\
"Rsa3odui5QnwBe1ldWaWxlKOUVux8ym4Ef+IfO/WZPPNvTyTOvHCqZ7RYVPIeHuM\r\n"	\
"rvWCmFI3z4K9iCW8vxEjyXwS2Rsg8btf+IkjaLtXKWthvHFhboM5BHCpwCpUiyZd\r\n"	\
"65PF61rmsiIBm0OsDwQHNyzbn6EBpCjeV+0FHefGe91ZYjmSgEC/VgaYXlQAzr6P\r\n"	\
"yMgCVhPI9VLpF1F5pS5Y9XrWxTwduCrufIB+nuR1F0gBKUl5ihKvtrg10mlhZROh\r\n"	\
"2huufEF/EUCJnLAfaRXrrMNXXqCCknT4p3t/wqEnVemBP/YfztcwOR0j2BCcMHLm\r\n"	\
"iCCYMPuMVPFonpC3Gj2xrP2FKFlCSXZ5ys7b04u4MyGpWWDWPyYUk6sX16xrQ2ox\r\n"	\
"77DVw4gyYV0xyeXngGSYw7DpE2mRHmw+MxB4iSWpKo3fmCCz6yppd2h3eyzbq7zx\r\n"	\
"nA52o9mlQtKKVMJ0aakfDgn07qG6fxVBSTR77RI52nUvoPlR62fd/ZrsaTFExHXV\r\n"	\
"k0O4hxqodb4+pD1FK4ndyLBtKgtPW7WzhypC5HB8GmpLbjD+62iyIcWOoqAxY6HQ\r\n"	\
"qURg+s6CiOPuN3IuxTZyOKchVxCrLwX/hLlZqTs+MAVoMG1OukEwh2EMp+lcVB2R\r\n"	\
"chGUJLNSqCTqnrcr2Czjbxo5Ug80yKKZXNGVFfniLJwDcnt7l50LSRnaitcrx8o1\r\n"	\
"wrlF/MbQxHoWofBCgSUx0MUlM5Ci7OezScnIRtDuqT9r7LDTyau0fQg6SLPVdEz4\r\n"	\
"7ar6DdNpxb1oyEcJH2C5G8q4cuOj1XDhVCW29/mWqtF8AxcbWPs8ROy5O0hFqe49\r\n"	\
"KnXpUTshyB7Bcjh9ltPesSJueILj6ow6wT9W6+63NTBkrpOAA0W+AwYrw9n1uyGz\r\n"	\
"gPbiQurXIHTND12FJFBMWLV+5Np5jjiK83WEXen7+XTyBn8hlt9DOC+/rDDEU5Ax\r\n"	\
"asc4NpvFTR9ZzECeRHja/EuoCMOBpYdJnuNz7x2dIRagdI3imrUSsBCWQkUvxn8J\r\n"	\
"k+KSKeMXPGsnmUaE37IcJulBsieijg576urSY2zxZ+7I6PGO6OkFKGBvXMILyMiF\r\n"	\
"r2+tK+e7dMlJZ2xW8c6J0/q2Q19bhOeohf3Oq7dWjHypQ/K+xIFj8BvwL+R1rJ/D\r\n"	\
"aPd9I6riD0OR3yevBGFlGv0cS9snWV1gWpebTMtsnRrc+ce/+AgG3yJN8l3SFwPY\r\n"	\
"JtIwM5998PiW13bHtFX1QvHbZr7NqzCf5xQ3ZKHadj7aAKmmUidcDmQrULYPEZkp\r\n"	\
"nPl0eY7Jp7jaM8DLGwMaeXv5m09xwjXmsY732MCp+0LzInEtLl1jYJ43T9W57Iyd\r\n"	\
"mibJIEA2plLuB9bx53DBBZ2bFfes7EmIvIUnJPOdU/1IJ5/jvm9YEUFWrf534spm\r\n"	\
"gU7bK+bbSCojg1QgxIdE9JtJEC6CKDUve9ZjFY3RCRXU7y1YiZdy6/E/udTk6OVa\r\n"	\
"6eRAae3AEbD3nnoyqWNY4SQWTfvF7gHNbiv3/EgXrfmVTXDDHZYJGocF7UmZx+Vm\r\n"	\
"gXgLZM4JmDfVK8aT+KQWJ4vV0RUtusc18H/l9jpXXkXVEj/bjFVHv0CCfl3Kv7nY\r\n"	\
"PYHrrFkvNEVl0j7/nhRw3BYV4O3fP/rFCMaMO27eEyZMAzxj1Uzs6V/s+56u9wN8\r\n"	\
"k6dYxHathvt87e8bGnrifMQFm4IOgnDFUjSh+hnIvt+gNZWJfX4EOjyyJCBKqFhT\r\n"	\
"BgaAeHT5Sc3KeKjkbU1XTY7T38412Q676fvhMyac8ZTDXVFPwwfwvF+7LECZWjfr\r\n"	\
"KgKj3iB+LOgS9GH/ubdnbhbPmN+K9vCYkggq4antbGZ7fFm6CwoVdvE26FFIw1RK\r\n"	\
"lowWQUIXsT8ln7dCwQASWDtciGLbY/9F6HCuqi7gc8iBEIU5+UNayZAFqukBRTpI\r\n"	\
"G1AmB9kXjuiOYY2Y2Gsiq7Nju+bWk8JUca2PqGGxkqvUd5rI4vNd3OtthktMwYKe\r\n"	\
"rAlVcaVpUuR7F9+cIYoffz6mqLH1Xxw5Oy5H3NIgpDXkAxVctqgZFoDgl7hm6lR3\r\n"	\
"WfOwUe4+wN6UmThSb+U75E8vVtxFo+1dyvJ4ceSfwTF7VFs0M/ZkatMYeS2FWdhf\r\n"	\
"szcYbpz4wFBhDrPBCz18trSzg20eP2Ui5K8MWkqqrpSQTnktovlPqS4ScOeYZLQe\r\n"	\
"/nyvz9akzUSzV+u/RnsglCx+FH/6DrhTGnq4DKHoBow4g5c643Fn7rhqnZgUZAs2\r\n"	\
"9cwXnFuf3WOf/iXHGdU6/lIyqLeRqfsf2dBHM8W29bIgZyLlHxJBWuAzACJgcw/o\r\n"	\
"LVQoDY5ESClJMAfG25eAXC9Yo5wM37Hp6Jdaxf61QWO032Tgkinnb1KhsxBoiQp8\r\n"	\
"d/uQxm7csD+8HU1dwAp7+nEM6Tkw5sSvXWh8nmL5asVBD7i97qfQm5nHiNgRBhgj\r\n"	\
"x88g3CLmKmO1EgDYzihyTmSyCz7GKP9TnNoX/BEpnwHfty3DY8PZDnO+Lh6sjuHW\r\n"	\
"rZjMIcNusMs32Pmp0bBqnc7l7CwxT730gBqwbMIKaIJ8+06oWOvQ9RffuxWBRoRn\r\n"	\
"rtR3GXh8++S0PSf3xbBtMjIIr4Aok02aQpqa/+wPyS3CBlTSb+dFYUwB8IfLbBOO\r\n"	\
"XG0Zp/13H/I1Y+MIXGrKFS/+gkz2aNXNxv1TMJUjTmT8D+NOAAop+bwpus/7DXHK\r\n"	\
"lzbylUNfkHXVUP7mDIoPZD9FM6PcEmsh4UR21clvUsBS5xCBJRZsOSxujoNnoYpm\r\n"	\
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
 *
 * Test certificates and keys as C variables
 *
 */

/*
 * CA
 */
const char mbedtls_test_ca_crt_sphincs_shake256_pem[] = TEST_CA_CRT_SPHINCS_SHAKE256_PEM;
const char mbedtls_test_ca_crt_sphincs_sha256_pem[] = TEST_CA_CRT_SPHINCS_SHA256_PEM;

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
#define TEST_CA_CRT_SPHINCS_SHAKE256    ""
#define TEST_CA_CRT_SPHINCS_SHA256      ""

/* DER encoded test server certificates and keys */

#define TEST_SRV_KEY_RSA        TEST_SRV_KEY_RSA_DER
#define TEST_SRV_PWD_RSA        ""
#define TEST_SRV_CRT_RSA_SHA256 TEST_SRV_CRT_RSA_SHA256_DER
#define TEST_SRV_CRT_RSA_SHA1   TEST_SRV_CRT_RSA_SHA1_DER
#define TEST_SRV_KEY_EC         TEST_SRV_KEY_EC_DER
#define TEST_SRV_PWD_EC         ""
#define TEST_SRV_CRT_EC         TEST_SRV_CRT_EC_DER
#define TEST_SRV_CRT_SPHINCS_SHAKE256    ""
#define TEST_SRV_CRT_SPHINCS_SHA256      ""
#define TEST_SRV_KEY_SPHINCS_SHAKE256    ""
#define TEST_SRV_KEY_SPHINCS_SHA256      ""

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
//#define MBEDTLS_TEST_SHAKE256
#if defined(MBEDTLS_TEST_SHAKE256)
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHAKE256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHAKE256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHAKE256
#else
#define TEST_CA_CRT_SPHINCS  TEST_CA_CRT_SPHINCS_SHA256
#define TEST_SRV_CRT_SPHINCS TEST_SRV_CRT_SPHINCS_SHA256
#define TEST_SRV_KEY_SPHINCS TEST_SRV_KEY_SPHINCS_SHA256
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
#endif
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
