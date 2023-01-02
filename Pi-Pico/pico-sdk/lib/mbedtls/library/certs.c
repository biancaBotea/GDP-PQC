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
#define TEST_CA_CRT_EC_PEM                                            	\
"-----BEGIN CERTIFICATE-----\r\n"                                     	\
"MIICBDCCAYigAwIBAgIJAMFD4n5iQ8zoMAwGCCqGSM49BAMCBQAwPjELMAkGA1UE\r\n"	\
"BhMCTkwxETAPBgNVBAoMCFBvbGFyU1NMMRwwGgYDVQQDDBNQb2xhcnNzbCBUZXN0\r\n"	\
"IEVDIENBMB4XDTE5MDIxMDE0NDQwMFoXDTI5MDIxMDE0NDQwMFowPjELMAkGA1UE\r\n"	\
"BhMCTkwxETAPBgNVBAoMCFBvbGFyU1NMMRwwGgYDVQQDDBNQb2xhcnNzbCBUZXN0\r\n"	\
"IEVDIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEw9orNEE3WC+HVv78ibopQ0tO\r\n"	\
"4G7DDldTMzlY1FK0kZU5CyPfXxckYkj8GpUpziwth8KIUoCv1mqrId240xxuWLjK\r\n"	\
"6LJpjvNBrSnDtF91p0dv1RkpVWmaUzsgtGYWYDMeo1AwTjAMBgNVHRMEBTADAQH/\r\n"	\
"MB0GA1UdDgQWBBSdbSAkSQE/K8t4tRm8fiTJ2/s2fDAfBgNVHSMEGDAWgBSdbSAk\r\n"	\
"SQE/K8t4tRm8fiTJ2/s2fDAMBggqhkjOPQQDAgUAA2gAMGUCMFHKrjAPpHB0BN1a\r\n"	\
"LH8TwcJ3vh0AxeKZj30mRdOKBmg/jLS3rU3g8VQBHpn8sOTTBwIxANxPO5AerimZ\r\n"	\
"hCjMe0d4CTHf1gFZMF70+IqEP+o5VHsIp2Cqvflb0VGWFC5l9a4cQg==\r\n"        	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_CRT_EC_PEM                                           	\
"-----BEGIN CERTIFICATE-----\r\n"                                   	\
"MIICHzCCAaWgAwIBAgIBCTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJOTDERMA8G\r\n"	\
"A1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0EwHhcN\r\n"	\
"MTMwOTI0MTU1MjA0WhcNMjMwOTIyMTU1MjA0WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n"	\
"A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG\r\n"	\
"CCqGSM49AwEHA0IABDfMVtl2CR5acj7HWS3/IG7ufPkGkXTQrRS192giWWKSTuUA\r\n"	\
"2CMR/+ov0jRdXRa9iojCa3cNVc2KKg76Aci07f+jgZ0wgZowCQYDVR0TBAIwADAd\r\n"	\
"BgNVHQ4EFgQUUGGlj9QH2deCAQzlZX+MY0anE74wbgYDVR0jBGcwZYAUnW0gJEkB\r\n"	\
"PyvLeLUZvH4kydv7NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xh\r\n"	\
"clNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAoG\r\n"	\
"CCqGSM49BAMCA2gAMGUCMQCaLFzXptui5WQN8LlO3ddh1hMxx6tzgLvT03MTVK2S\r\n"	\
"C12r0Lz3ri/moSEpNZWqPjkCMCE2f53GXcYLqyfyJR078c/xNSUU5+Xxl7VZ414V\r\n"	\
"fGa5kHvHARBPc8YAIVIqDvHH1Q==\r\n"                                    	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_EC_PEM                                          	\
"-----BEGIN EC PRIVATE KEY-----\r\n"                                  	\
"MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\r\n"	\
"AwEHoUQDQgAEN8xW2XYJHlpyPsdZLf8gbu58+QaRdNCtFLX3aCJZYpJO5QDYIxH/\r\n"	\
"6i/SNF1dFr2KiMJrdw1VzYoqDvoByLTt/w==\r\n"                            	\
"-----END EC PRIVATE KEY-----\r\n"

/*
    SPHINCS+ certificates
 */
#define TEST_CA_CRT_SPHINCS_SHAKE256_PEM                                \
"-----BEGIN CERTIFICATE-----\r\n"	\
"MIJELzCCATigAwIBAgIBATAMBggqhkjOPQQD/wUAMDYxGTAXBgNVBAMMEFJvb3Qg\r\n"	\
"Q2VydGlmaWNhdGUxDDAKBgNVBAoMA1VvUzELMAkGA1UEBhMCVUswHhcNMjIwMTAx\r\n"	\
"MDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA2MRkwFwYDVQQDDBBSb290IENlcnRpZmlj\r\n"	\
"YXRlMQwwCgYDVQQKDANVb1MxCzAJBgNVBAYTAlVLMDswCwYHKoZIzj3/AQUAAywA\r\n"	\
"MCkEEQD/fho8Uy1zBoiRGUqUe3Q3BBEA17D3aZUyyxwTynjyuRlbvgIBBqNTMFEw\r\n"	\
"DwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUKqUWnFaeuqO7zhRj1tTbPVixAmUw\r\n"	\
"HwYDVR0jBBgwFoAUKqUWnFaeuqO7zhRj1tTbPVixAmUwDAYIKoZIzj0EA/8FAAOC\r\n"	\
"QuEAxweE3XTPBw/ntj2D70KbRCT3gYJWW3f1QDOHWErAAbJxPnerBVd5YcbMrIOe\r\n"	\
"PMJi58yOCL9MfUEFt/vh5LdwgjWTXINrerGjCakbfJJNAEr62zRcrgyI6Y0w7Mfz\r\n"	\
"z0LPwZKnjGRLpRoQaElzApD6+ESlVLF1W0iBWzDl1UjH6uQZaxQXRz3XJX7vHnk8\r\n"	\
"KyS71hmvVr/9Y2hBzVqge/dWpyfuMzxwUTYEnmMSKccEO7UcRSAE10BT6ViniaQ5\r\n"	\
"foJ+cV7qApfCZldrehiqy6NqCrjSbKVg9vPE0ZkYT8XsjfUPUcCe7j9knpfjlWLJ\r\n"	\
"SBhUyVLywH/28kKHUbrJvbAgHaWa3hYZ+pEaGRPWMTvH1eyDvm48kQ9xEsc7vsj0\r\n"	\
"zam18AMi4L2GTDRC2tKUywpN7eBPA7nyZy9Yo+N7IylQZG54IW8dgXclTjV9l9CD\r\n"	\
"u+YDSUh+5P8yZ4lyW/8ikpLHioApVFQtC9l6LurX2LW0ctR+XzNyypQAHS9jBgt5\r\n"	\
"0YoRLexfciTn4qPAktAP2H6daLroBXvjlMRgSFIBpA2fI7bhvbnkoRqwAZf8Od5I\r\n"	\
"klgE9YQNlgqkeTyPlakcPgLTfeUyxGizB0fCFUaD7WfIp3PFcIDccWJQR2Ba1nrM\r\n"	\
"Ar10vdD3znt2zOjn2LzahOKD9TKWI8F4a0HQmWv5wULXzuLAgL/mpgkrct6YecF2\r\n"	\
"lWT0xOO14oorNj92GK2y2Bi7ZFfG9ndbrO3BShV0WcUsnt5DmdVlp/KdPkQWdYm8\r\n"	\
"uZBhaOsUgHjM/f7P2IaZL9FbHlS0HMNJJFRXn3vP2JKfEqEqzIKL5aBw71Y4m1gb\r\n"	\
"Pvo/pHx3ulj1igC5mbe9KAfoBvkawCgZhuxA44q+Yka5CjP9LBLz1zpL5e9SN2/V\r\n"	\
"jP/8BqDrZmjVAw2iwgt/D2AZjPPPhymatGmolU3we8wXDPQfJB/gwCbL7WgzbB/8\r\n"	\
"8EocSIGLhwrC7RHCXaoS9yx3Ed0YQDkd1BOeHLgJPKrR5yK5UIy5YXWTHdieN2ba\r\n"	\
"7OBE54NkAv0zehBTBGoH49uN0B7Jn1mJk8BPBFaOkPAJAat5OHuKlnmMmNkiFsMY\r\n"	\
"tzQwByWu5/83lhCe2pRGl850jEP8WNtOq6NjsZQgsK6JeSgs8n8djLlpNZX/A6qK\r\n"	\
"4dbkC7z5deVn1Kbl6CCqUJCE9McPVHY0apYUXCmsbgWlR+PYWARJPm0VDbptl+Dj\r\n"	\
"EbyMw7xIhnTk+IkJQrhShxNFuQOc8JP9wNH49dkTrGyypKgOpLAjpaj5Ofg+nquD\r\n"	\
"VvoS1n/FkELEk/yewYIQ4HDRba08jaLEL1Ezv1v6I+YQXlHatRzbyBqFThGrqjim\r\n"	\
"xjRHF4cb+Xf/hipEi1HUzTzdqSI7C9lYkO61Gcy8tAcFdycUnN+WaoD9DNnE051D\r\n"	\
"p+LOEOfgAxBa8GmOYicC7mDFk5RRW2NHfVJuHZKDdmuTjsplAjgKbpv0JffVwTIt\r\n"	\
"hVzTApp6MQ1w3ePDD7Pi4o9hehRvQv2Dd7hMf404aWVB6BQTAlDdFikMrkO6BjFg\r\n"	\
"GZqgfBsFO19NEwOpNPolB9XJzJS3gZc5ZilsADj1LB6PS46+oIZc0jEMowcwwqG7\r\n"	\
"6OatwuetZSbHDCHi0SM+bPoQ/gi5Rt5rkUwjnjwkCo+pWggEpNMBAq3wczYyi7Si\r\n"	\
"7pvWrG7UYTsYbheHZwp0eT9d+AESN/zvbci27CEqhnh8cUhEfQCTFMm42XOYtNdQ\r\n"	\
"MWs1dQB34TlhxX/0G9uhWdjkiI4Dqe58CAvHyiiur4pZDYVkjjUI7PLL/lfmPynq\r\n"	\
"JBGSZs/ZqYo2gS7jjRrmqznBXRBZrL6B0qywfQv6quUCAfVlJHTHGguBQHR/PkP+\r\n"	\
"Uun9SLy6V2ifEAJH/FqxmlyerEDQUSibYZCoX94NxyLJl0z2UgH7O9L7RLzfynip\r\n"	\
"98jY8iEJBUiq4qf8EuFKMK5mv2J0eE/tl8C4PiXV2m+5hLOUuEW/b3I9612Fqzd4\r\n"	\
"Cn1RhKIKvMDI/hSNoBm6Ewu8uKb4BuyzZkUSKsVbjVwCTBNgr9FNsfD7OSdTAz+T\r\n"	\
"EAR9CSMkNQRt7b57WU9AaqxeJH++rrTst8doRMm3+B5OmToNfKjx6+oQXUjibYpn\r\n"	\
"iPNtFqP13Ez9WVDxtEo7N+6IrC6/Nokl4nOb6XdarjmtP4CmGj+T1/W0WO48OZIK\r\n"	\
"FaYRVd6lIuJImD89A4DoEv2ykhwqrVDy8ybGBn9cDa0WpdUnTwo+ycCo3YOIe+sc\r\n"	\
"YfPkPC616qolEfnR/uemooHHLON9rV4Ln/xfbSWVdlAgG2dmxYRj9ahsZnmRvOdW\r\n"	\
"056VhzgWsBdMkCbNDpNTCpn9J320TPhkn7yCz3sgJm2/UdN87UlX9EE3PW2mAPcD\r\n"	\
"MQkoaQxPGpoF/rFqJhK1TjH7ke21s72KFfi4ok08CZ5eTw6dlNibPVf1a68p0WNg\r\n"	\
"w5puFVhDHBLAYqafXRQpTzMr8ftUJoMnA+wbGyU8fl0SPgjCRr3jjfxi04aN9E6S\r\n"	\
"6i5g4UF4RpPBriQ8o4aI2uM/02U+sSwk6/5z7V41bGJOH/RA52v41hRrWZYy3bk5\r\n"	\
"SDshxvslN8INTQUu4GwJJZ80/O4HuUVbc5VY1JyyrIDVwk6WQ1giQ9cxMcRJYNjY\r\n"	\
"Z/n7ssUB6tVWtMF7o3Hwsb7uXMDpXCDRWxR2fz6EIbFtZcQAK1bXWQiyqpb6sn0n\r\n"	\
"dgbWUTEBZvgNBf5IPRNszpzou1/eiSlYzjIU5Zj11zComLm53qXUnoSHbXWdX/+M\r\n"	\
"4VjYdhaq2RdO7OcRVUi5eDV22+zldmurgE9LCDS+1//08fIZTxNBC099CoPYRRPj\r\n"	\
"5CicqOxAW6ecofa17qLl1JiHgER0ldG7eF+E2u4/ip5ziDAs954z9ell2KlSThRw\r\n"	\
"KFR2/gJr108yQXcJW0Md7paWh94Qyy2U7n8+vKONG0+N/SsDKMT2jh7Bc82AlxtI\r\n"	\
"ZXssq9mG+HrR0QvKUt9JxxoBNg0gBrb/+HCoAREX/PyTcv9JgwfoapUwctnfJWID\r\n"	\
"pJ8gImpkiloZiiv3dy258RVsGjJoLEYPLcTB8Xk+Oxcv147AgmZDJq63z4BYkY5q\r\n"	\
"kD1VdKLmKhuTrL+slJZzn9esWPxl3MVbjeXGtdf79APy/Cr1g0b7mZAQxv42p4L8\r\n"	\
"xCRNcUS12Ph9IZFI+IyzQq5cfI8zDXnfGxSv/uSQhWZ4krQ+UIs9b9yBMV7K/ecG\r\n"	\
"LpFfZchomIXyF/NFsa/06rWa6xmC9ogfjNpBbiQwhx852mtYfasY1XCYetD+NOgQ\r\n"	\
"/CfIo0gfF7q37IO8JUdcRpJ0WLB65mBOoT13lmyf5+RWOAC2+CJ39On0o2R4GIn3\r\n"	\
"x85H7EN5qMgjO8EvmXOuffSfUvgIF9YReZ5831kUwQK3MQwezFx3K1M3vJKAiPa6\r\n"	\
"CHb4XxWSNZswAWzVFbtBs8rstLjUS33kwobUI6Xv3GlTaChB2Z9dm1gtv97ZKp0J\r\n"	\
"exnh0Lkxmtr64bejfinKf/942DgCVZJg4WWkqL6ookZEPqoisGsxRq3wW9lG+bWT\r\n"	\
"Q34w2d9Xlk72THpYgXmZv3ElkXEI5aI5VXu59q4+A4w7Ne6s8/+4DYB/JSVLjz7O\r\n"	\
"0M70wS8CPQ39SshMFvpIil4XzfdxWgfzOOvPUagxYRf7gApJL6AUpacez33m8LDW\r\n"	\
"DjxdNmrut/fkvPvOF4iKCR1LkxsI0P8ENbAzBrkr5jwbW8VwzmKpJZ6NKGd6MzH1\r\n"	\
"q8/PyyaI1d80HJ/sYX9kiKIr6nM9NI249DsY2UmkhXM637/GcZKyug0cI4fncJFb\r\n"	\
"cBYRemlVMrtGwEDVMK17Xi+ydm9uAIVcqL13vRU1X8s1uR6uFPutH5uUvmjshJiW\r\n"	\
"AxBkqS5ToxQ4U6hYRvXex7JfU7E1A7qC7nmWjw4LWbiv0rWLccGXnGaS6oSBfVtY\r\n"	\
"v4Ez7nxVFLaLOe6GhDZrRl1YOdG0Ubr0Iy2Iwyp8j7A0c0YiVR82DiN4JWSv6/HM\r\n"	\
"NxiSRk6SUNMDwuofuXwo3lTpvgI6QB8Cf5jQ7zbdjT9VGqshGjm2pgvILgSZq2G3\r\n"	\
"FlJmNs8qzyN5lJCvsfeJK+7+JYJNdtn58hbWyc0ADXaiC864r4LDhKqCK9j/dTe7\r\n"	\
"Osbiex0ssiyM4jn9p367OyIIC2CU2pHHwfjpiRBp5vx4ILNRkctsgpOXatve4atq\r\n"	\
"i3zS24yQrbzbIVyEiZMkWgP98fS5q+rSBpUJ1OleUcgnMyT1ZnPAkXs8LULLL9Tt\r\n"	\
"c/884Q9YokEq+4U0oe73kM8r+lBcBfXGIyUvqrWv75DG14S9i6WWxGUF5Q2WslKy\r\n"	\
"4XgnmtIFXKqGLKsmVHsnS/fB/vdM1yuD0eTXVFcYWg/9DJVqKWnr13d0w9s18lps\r\n"	\
"v4sPi0tPdeKEu8w7luHJ4bnMirD2PXfhKIHh+sruY1cSfK7o+NwlovYHg/kYVVOX\r\n"	\
"PP0cC4qec0xmXs0eJ+Opaem1UjdbYRENGgnX69T0tG2STn1k6ouDEWar4/KUv9a8\r\n"	\
"U85ZpI3fTYF2eOKZ2Staxga2JRkJBbtS9KejZzV5OMJStvgAlE9KJC3E7q2XbqQD\r\n"	\
"Nq+MTcIwprfzKw5X8vns7aU4N2Hm3veSMxS7eJO/i7+AdhimOpGPajLYT1+PyLNO\r\n"	\
"sT9X2PGnapW2gUqXfBV6AbWpRm/f0Yn4jQrw+MPSxOR276BG0bntMP6OjAwFTBeQ\r\n"	\
"10W89TtTdK0DUsDWqcBl7B5+DaEi20Pj1skF6TO1e/vShUqJb755MqIPXKh3Swq4\r\n"	\
"OiGIrg/wHZT7oLnDi8cO99ROlGiobNKxlygIe6DdhPGdrD4D92/DcFN575mzLnhl\r\n"	\
"r3ItzMRiw4NRrMMaWiFwWIuwLL3ph82MxJDRqFuW5rhMmqyrcmkIJWFg1e/QDLeJ\r\n"	\
"NiF1f5ouu9dr+DlegHEh66BMvNISj2RPY5KFLNdSbXg30DjTMNK/ZYfSFgNzjqlM\r\n"	\
"jf0peUwEwZRLRCrGnnNikaHzgPdC8zRnfyL/rUnOE2IZQq8rXgcnDQGD6Rw5yi38\r\n"	\
"iBCL3gtdqaVND6GoT/T23PkM8I/49siAuihQN2i5NTLMIF0RQoVKsOOJBUzCfBBu\r\n"	\
"oN9wqJQ9wsURY7ALvyYWt86w6F2f1EzodON61uzCv6DKkoa5R8AyrrkkoU9YmB83\r\n"	\
"KuCfld8bKPm6cVBHsplwUJRfUUB5Ph3L0A/zqZ5BohoX3mFd8jI4iBgXxKMD/j63\r\n"	\
"PDT+4D1Rc2v0uVUa18z234+xldUB6bTp178xjHjIImv7ZukrkQe+O+2ImKPLBciq\r\n"	\
"ic8VxmNNbJmW3SDkaVoL/pctecY1hKPuQdc6w3UI+8MShZeMtTQNqATZxQ0X75MB\r\n"	\
"eDFXMMsdwpP9E6BNzziKdvTTf/Z3TUZHnz15abCgyI1SAfql3F2yGK0vyIavA9Gt\r\n"	\
"JmC3Ku5joq4FIsV3e3f49hF0m4N/PWdQoHjMs4YS3G1iMzdKRxWW5A+U49yqL4qw\r\n"	\
"f+ibF8+PGxQEGm5LRXdcBrOOjIUcssDtJzmd9hxERQVt4t6P2+cy32Aom8Khnnuq\r\n"	\
"rE6LrjfF6zFS/jMaED6me9UK1F2rDyT/ps7cfr5x14gi6WaMGBhcLphm97QzvxmS\r\n"	\
"oD/ccf2lpF7GoaN3EWVONFBT3FVJzxTOsE0kqKw6yt1rQd2HhFY5YoZUx0XoO7IE\r\n"	\
"97q1UtP/gl2dw630i5B/TifiGeZ0Oq1KmSZezm/5KUI0LCHrsHtSBokv+6qDhN6M\r\n"	\
"VW2NGGdt6lfTvUtkgbDo7V2X2geE/PlA+gRZ1RC9AaiPkBNGAJ1vpzimY/WfFkbL\r\n"	\
"sWVpu8U+9P/p82XYSVn/XBSWCipRhscSma1/VCgi6OmkxG4bV9AeLvXQmZd7qqBd\r\n"	\
"L7qFEcDqLfbupMITf+YsYpLtxSDKnEp3VeDyD4LfzgQE1fJ9U+hSqGjgRozRnsU4\r\n"	\
"KbBdE0KbNsXkVrtfgoaQtv6ia/HyR95GZHoOKwUdsM5ppjOXSgSaYxsVqmhOlmt6\r\n"	\
"MMkT0E4eVdX4zAvEMymCgH2kjk8vPCTy9JN+hzn9U1Eh6iAY3bTL11xBcCaPAhLx\r\n"	\
"R7oVdQguPARZva/JglRddk/a/REgW+3ZRtUEGXnD5X5EehKomlgQMp3pGXHq7/fq\r\n"	\
"IdpByXTpsFbIjXZ95BH+jdPUM10M0Luj1fNSu8PTGLa4yLNNzABfCjVgdNbNhQNe\r\n"	\
"WJTvfE6KgKrS5x9sZD8nQDHdOPgVVvcGuO+7eBZ7/j21JA1OdjrJHs0jgWpJRB8c\r\n"	\
"Kj38nVhLxxBH0tx6FoUfS3w6kVantBVNoI5D2mf+ksytT4Ey4R1p4nVsqWeuTj7e\r\n"	\
"z8vALBFQwELCmn6KPXS2v3adYQEbUQW4kdWs6ZHO8iVkOrjKua2seOTmXlJDaejl\r\n"	\
"sp7s4nY5zFrbX+VyghiihwPcGPb595zlIenkEquVR6jujnrCrBPPk8O/QhrICofM\r\n"	\
"cPhH98LMCaob1graL+TfNBGXmEtoHtE95DK/ML5PUk7FSPViGChDKUZ/zJoUWbE0\r\n"	\
"t8YuZxldqgsjgWsIaoUYdKiOZ21iQZCRRM2RvWK8y87vjqMYo1OounR7s9lDBuVa\r\n"	\
"/k67LTzXMBLNDkxcnZen5w0Lh2G79w1JsRgs46kCYVIC+gMf1MSkEljjYGj/LO1X\r\n"	\
"mZ1S4jB+5ewLl3PkXsXdy23FtDKn6xb+ATDLLVajriKwCgYRpBmcnORGB4Xy2ShN\r\n"	\
"cGf2YkBVHqCFELgTD2Mjq1CibaS8vCBHzEqp867yop90VzhlmJNTfw2mRWGUxF+i\r\n"	\
"TroR9+DjCYeupiMTjwm25DQ97TDqjuWQqqg360PoOBolPpsLhYquhgil7AmAmS60\r\n"	\
"AiVCNSuIqn/ZStQ+707IDrtzO4+p7U69L5+c3EF3BgWoeqUUzUPYqV73fXhrJ5Vw\r\n"	\
"WI6oQCaEAVWMFcr21mSJU3pzISumj87/OUlvNIX5qhsjOoKOGs/EOF62Q9lMJaHL\r\n"	\
"mdyixCLTdQvi9XVZghQiXxjXObc+kd6O4zEvrSvayh++3+6WXtFxF0XVjqjGDE3I\r\n"	\
"DEJjlkplezxz95JPw0fpITHfmhXCkCVOEt+ehMWH2jrbLWuDdD2Za32+mxHDMQ9W\r\n"	\
"ar4OvrQD1hWZg6VUPFEL8TnLvFeSgyhIBNG27tegSCdiaMgMSU5QoGNo2OKhXftW\r\n"	\
"+7NTpmYz+NvMwfEyJrwsiH1izE4yS0pt5PeE45SPBQ8rO+X5yTw6jvQe4zSYMQpT\r\n"	\
"hj07nub7iVPOU/Swh5oiB9dSixUFVijQFmLjrDAWUKcdaSnuUIg1Db2q+UppPQ14\r\n"	\
"s6BVPSaNKmZa+mX1rSo9xmyOokjTrlBCP2eP2tz9au2+Ls9mHWIy5lXn4zuNfI8q\r\n"	\
"rSWBNtxC7luDONALKltOm+SJhJzkUyHCJxYCqBU6smofc5JQqqpJle2y387Zqs9c\r\n"	\
"zyDhXppAU6wCkS+H3lDh22YmWP03CoKFFPqJAo0826Z/p2qWrrE1auWCJmJBWhbX\r\n"	\
"BF+vGf9FMkK7CpE4gshGEWoXD2q4SmlSZhSOlV7eBTVRH4bu/LIjPdE0FfnkQNCP\r\n"	\
"epurkZbhOPx5q5FoIwQ8CzMUkfXRRY5rVwzZS2hJPKEDRcb1zzmESV0B2C0T5g4Y\r\n"	\
"3kLnOdqCN3h69GTYgY0kajqj6yVoMqARtmLlY1fh31C3/3RGcg1GFY7F80Ml1Ny1\r\n"	\
"d09UNzA7ighfstt+WREgNWINGe/T3oA9GI+MLBMJH5przAqsxw3lfIDlx00WAqkh\r\n"	\
"eL4Ui0LitVu4NBW67cV3HKH6QVHDzYyjRtUNKkwZvK68G+Fr3JRXfJAK60KwOSm9\r\n"	\
"MOLg1cmpqL6RgPLvtAtFFqYepwcZ8jlnAPylbzQSD/xIQSzexA/9H5KaQ05Oze1i\r\n"	\
"fW8nN1VT/dCxp482SAzXmCqUxGUvUxJBFSClFLmKbAN6C1WaQaIAa6U43hNuztA7\r\n"	\
"wp2K3H693g31MIFKM6NhLlQu7dJAlBcgnMl2wYKdsBIvui2KvgczDmrbdTmnaqfH\r\n"	\
"iifskftUQCK9ZZQWk0Yzd5YzYRy3OiKGGAaUZjJgrlzuute9Wa3IpZ2RoUTkh907\r\n"	\
"wTI9iGZ9egdMeSMwHgpYehuAmcpxevbqwT72fbH+8tS7/+lknwlNb5fJYpnmBxg4\r\n"	\
"6RdCDn7YtgOwh2exOS3uxklfroxEchLRl3BKPOFfsdfWdyn+BUH8oLG4lAJgoCJP\r\n"	\
"Mz0p8Xs9aaj5+H2a11i8Wujn9gsMZFmAZX6R+fKY9Lmd3kwixopaMjmSVtrFMlx/\r\n"	\
"wWTAGT1up43biwfIuP9o5D862huTyDaNa2IJR3zVpGNu6KeR5Dk3fGuS6UfXKaYJ\r\n"	\
"AHkwQfkgAtYwYl8iVyPUqmtoptobFhPFknd6iZWLplinyKvvzQ+lQQ3QtYJt+u5r\r\n"	\
"pYesl6Ba7zI9hqGKVnGLrT4RNGVNa8br8D+5njDDRzTA+zvnq9nluUf3sV6MPFwx\r\n"	\
"1FEqhLQKEirrSE4eVsZzhdeud4HInf5GENiVudZ+lLG8UPWZrfceTfTAMKrGEVTT\r\n"	\
"yFVYH9RKToNEq96p8ZY4RfH4tiZ4u1PsuUCGzVsfCVljPJjj43mB/Ubc8Y0m1jx7\r\n"	\
"LZXujDtZyfydBOFajOQhjEZgNsDOjYh46OoJfHrY460Lj8LGmwSS7bSDW5WJjcrU\r\n"	\
"PluOREOI86T8RdAiZaM08WuVeI8vUrj7lfdZj/Cqgnd+9+AVNbnArQZzhPfkQVSs\r\n"	\
"gzRifPBhAcPly5ebvaRQ5PMq1t5BCABpKijuhAx2Zu0Jzxx2TZFiB9H9RcWf8lob\r\n"	\
"CUYJiu9x0vlRjoar4ZzlJm8kNOtm9nejYk0E6f0m4EMtc4V6a0A+NXP9v3s11P2/\r\n"	\
"UOAnWxVGzqP/Urm0veuhRW0MvlLon2Ek/pRC2UrLB3rDsGC7h6aMkRjp7P0Fp8cR\r\n"	\
"+62IK6CstRDv4PrdUTxeqOcevcJYPrw8zbCc6M173G3PneDYyi4K5jQVhtUwA6p2\r\n"	\
"nh+Ba5Bi+0GovCHxy5UIueksrwZAw5SYEK/7udgMS2tI3bK2+/aeDWGnSRHzW173\r\n"	\
"VcQlxySdxQp0viyz8NbBZzDKeD/CDXDy0vwbwd99t4F2N0P6d7bInilhs4TwSQGM\r\n"	\
"JK/0wcbSgECTDZgN9AT3JkXibaU7YriL3cTHVhM01dWs89g4xm8sKexH+fIWFbj3\r\n"	\
"1FDiPzeiP+KzKxCJjvAFQhK9Od8btuqxyRQhZufIsg3k3gK13yXyNPWRdRIhgXMg\r\n"	\
"1b68ktnhV0bHI2cxYvK16q7UMzBylnMtpAY3McpQ6Y7Oqz0PqUQZ2KAeYrpG6ooX\r\n"	\
"+17UVUCg0+hWg512zW/4Y0dL3twF+UVZYpk91cb1ogl5WSBjPAbrdwgPn3ZGAIF7\r\n"	\
"ofHqVHV5xrhhrjCpccQQKGX8cGtQTuf+NZrHGfvu6b41Bh2C/RD6jjWPML4UKxFk\r\n"	\
"WH5Oi+WqlK3Vvrhdb4xpd1GF+YViVcMO1ZfBpcyNxyZNDMH71yw6/me0Dj+hnKA1\r\n"	\
"MdHHDnL55Qcz3duxO0SHEmKSV18xOcP187wNvnL4EIJUD4fDPjRSesgg4yXHuZuE\r\n"	\
"WpP2Sy2+ZgH7i4FN1aKlDcNwOhrzcejF3+VIg7UIRcv797AF6pnux4bkfT4YyUAs\r\n"	\
"umTECzKudvPUQXk9ljE0rL5+Dr60P/sTMYK67t0Q14rvcRxjk/3FopXQd6BU1VH8\r\n"	\
"PzyYj/JEoCkoz/vGpeoHgyaSMCuP6p6Bl6oAWS47SmrDLJavTIH55DQzSvTqQr0e\r\n"	\
"LKRcONO7lrQefbtTr5E4OTMPtMFtUo+cNAhC8YFkjf+svfXM3ACPBKxomqmmPcaC\r\n"	\
"1nhnRXAtRt/rWpeH99OCVANGW2GH74yKESImqMe2pvOR6VRolZGb8gz8BcdUC7rC\r\n"	\
"6y8riT70Ioi4joLIx0hesIcJhTsrSIeHm7C5ZJnKJUB7Mw/VJTur8Rrz7JrhftVy\r\n"	\
"p7/g/iqmFjrTQoRteU3yn0cYzjCJXAhuoZ12JAH1He2oSai2arMBEALjnFvQpakW\r\n"	\
"1LyWJxPd2dwSFjkwL1K4fX66Gc+oVO2dQbmWrSDH8vtCrRE89T+Ku9KDPr8UN9fl\r\n"	\
"k14ygWodUuzvmeCDK+EAKZZUwTp/m+Cy7vt51tuW14i24zixZVcpEK3KNr7yZsZk\r\n"	\
"V4b0Cd0xurenDTB09+rjEUVSfb0sokvC2C86Fig6864oc48WeJe7JxhLx3Iu0Cp3\r\n"	\
"7tqBr1sItnlgf87ctnw2P8EJNE/CoOyAjXU4lCywNOyOjLNVAXR2ttY7CDjAwbYM\r\n"	\
"6MeybxwyV2jIw3bBVnO+uvaePumyYMvyz/HqW9qmdT5xgiy/k+W9PYyfmVUZ99V0\r\n"	\
"csxeHeHfkOhcITkQpZ8Icu+FSC0nk++p6FlhNO7TZb5zypUJJFpv9H22WFKISxZu\r\n"	\
"PDpNS0CNEWtx8flXYsKHxW8iWfZbBWB9MBqFTTW2HFdBSNdu9YfZMtOhu1v5175o\r\n"	\
"D3Hj7V3VD8U7ar0YjQsBZYdZ6KgN8I6sbO4PzMc1INhqlUK6DphlmGKHj68XObdZ\r\n"	\
"MmNSuGGj/PRpZWuLJO7xoNeZ85PdHDgD79pdYFU4H+KTqQLwiP484Td8SuFNLU2l\r\n"	\
"v34hyHfFO+TmaVUDgNr2HyV9oiLLTFVAxpis6FEZH8CsNyzt4oSeYNzSDzDuupTp\r\n"	\
"2kiKcw/uveJKMtoYO5iklK+Xb0+IdIRDLZibExl8QU5Vr+RcG37Pxs6mmRXQ29O1\r\n"	\
"kDO85VgjkV/HSa7o9Y8XUcRm1wMYGllFLL6tVJq2Cx/zREYk2INXkxa06xTffR0s\r\n"	\
"X7+ghVECnn/MgEXLrk6aFE9vl3OJOviiPZZ+sh/1m+hewXqCPyo194z3P5SeQOlC\r\n"	\
"YY7DbHcm1P+roaUAao2NsF21vQKgUK9MEauK/ZU1AJgA2NnLgt+tXouzNoQ8yGK/\r\n"	\
"xVc5rUgeBW9rgPq6p4rDCjAU6jgiixCSC4jLqRGkOA4YkBV9Fp3GY9VJFPjRsXlY\r\n"	\
"2gRw+bARH4h5Kw8toI8Sa0TLw5O0yp/abu276HChsVZe5P3NPU53fpu4kmpB17CV\r\n"	\
"Fow3Z3KgZ0O4Qt0oQ00nFbyiTsdNXKhbE0iO4/GCM01TtYZwr+QkTynyWT1uP0Ds\r\n"	\
"62lrVjVxL9cw45EcKTFGgws4Y47ooujL0w5NPkFiuSbq2B602gFw8BUgw18ueybb\r\n"	\
"fHZsFCNxWeCPTtF+Rmt1CG/c3mCEouCctaDAU3aayeCofOaZkXdD7f2ChP7K4nSW\r\n"	\
"mGFf6LkKMltRELLTXK01W0cD7i7yW/NPcp2lzeW/Y3vjBWTIztQ8N6z64fFnHirx\r\n"	\
"9LMBgKHfZE1nscNq3YQxnpXwwmXkEQqhOIibxbdhXwMDAme04psZTCM9YWxDMfvi\r\n"	\
"a6zEcu6kOZ2SyLp6jnnW+ksk9Uxp/+fg1hF24LOQbSF7pjHiulA2RacOwh+QO2qJ\r\n"	\
"n3OxzByLVOWo/NZd9mlEqykfm5GKKIgL3ptqTooitb7e3AaRA34nTH4BYmMh0O7r\r\n"	\
"gRkxIDBRwI/5WBNeHaFfQXIa3rwWRczbEedH9SRXA5cSwJHL8dHcXz/StWQSZyZI\r\n"	\
"XwULDNQwJ3InjIahtS+EJ46JtQsBbDImpl2soW3sjBfaHgRdLYCi9ClVrcHXmS6v\r\n"	\
"GXbGN33vEuwnmqvbMdrMx5gChxzVlAr+bgOJsRLxXBjo2Iz7rxEFTZuc9E6bFIGa\r\n"	\
"fIwVovczfwV4l/8RIwqtrQh/UVGV6mZjbNg05B6+XaEMqHJ2XhOCDOHuhFTPx5K3\r\n"	\
"Pqd2dg18euKqm3JG4BJk1HvMuVNSkTVWSr7lsQiseA2jv69AB8NydI2h46QfVMP+\r\n"	\
"wPUh8wzXOMPAYtWNiOLH6SQ3Jw5x7l2FjTOTkGSDMAVIe8tWtn6DgGaeUsSZZlyW\r\n"	\
"C6PazdjgKwYwsoAA9rOT8GZGdU8fgE4iyQ2rRDNOFuhVFe/f7wI44+YzF7Semd77\r\n"	\
"r2Cnp1xIQrv4UjN70oSbFFAxGQshPVSIWY3QMHJu5XQ7A0VE3z7lxSyHudhDYMK/\r\n"	\
"5NrxJUhvV/iB5LiIPtVHenxYbgPFajbSuXKGGd004TIZMjtyLRLXxOrgu7ItW6PF\r\n"	\
"xbAIpluQM9zvdGBFU2ytqQQ/0oJkTz6OaWNj5tfZY42zD7+ul8Avt6hO6vPu9LQp\r\n"	\
"+0czCcAs5Oau8PNvw5K0IjRnpUSkh7H0EcDGy76VRGHtPFr83a2BXV52JUPc4vCZ\r\n"	\
"N12LWtZ31Z+sueEycUCvWbYkbDMuIjipI1fa2Er/XcWIN+r/zHINiY2xWW5tM41B\r\n"	\
"nCObLo+LOXMANPC9Zf7HeJEsWSbyzALULuxuvlwipEyNYWCKWcgceuqHabxJblRY\r\n"	\
"lGpzekalul5BTauGgQcTctH6BnZVU7VoduHF4xqUsKesrpEBf/0V50ZXKzVjAxxm\r\n"	\
"dT7L2TXcnWm8W7eTl3RNvcygfBT4IwZ7KfBexxYAxzqHAuvXjo5CI3QaBTScSkQ3\r\n"	\
"WC+oUJ2BGV9M8cHonXRlE6GgiKz3LyVlZ64Xt/bw+4VaHR/yq6uTUSoVHhX8+5ZS\r\n"	\
"omCMk+YF/NciWTTYlF+CxA+q66M6rLNWozL+0cYgkWEh69RZA4RZ1ahcXFDf4x9F\r\n"	\
"iY84wh2CW6VciuSlmfgUYO9zg2HOZpCBrV8yjB/n5qfnfd8wssH4vhImoSHT1v7e\r\n"	\
"O8JWJUYWBkewL/392cq95415a6OfYQWAmfCEk6EtaGrjGEfWL/E6CiETlKOpYifn\r\n"	\
"weuv4zZAJROmr8veLUb6Sx+K5qFy9aq1T3Uv/4EHohayGBkNt08FE5QYhWeRWeho\r\n"	\
"qiuc01RwvSEytwz4b+NkFGCyK5OJi1kOdZh/zpc5hkj8xjgEqTw40H6fu4at8ns3\r\n"	\
"k3IKLQC1RRpeTEDCH7hppHg/Iy6vG0YTK1u5TdvWer0AdsGp0JacGbFcgDBzLLCu\r\n"	\
"y8H2IB7sBPuPddQEuEykxNJBNGcOvQl/ynsFU3DZJ2xjPp+uSS7kE/m9YcRpE4Al\r\n"	\
"o2HjNY1HEmDP1dPuE0Up0ufrO38sf0Gc52VvMC1noVEeMa83EWvdIPg9szPzJ29c\r\n"	\
"guRc7etUc+nz6Z7K6RcULFwFyI5pXxemS/4TVt6w5raeNPCKk5YIB/w5pTQ/gRCe\r\n"	\
"uhsf6zc8e+HFYUzoLz2yhcww1Qk/uYdFcwTl3Sc6mwhjzu2EIk8GhM2N2NMvDIRm\r\n"	\
"Q1JPoKNWb5OlQQGx53NgI0rrzVwhtCkfAAsXASRV9//0aVgK193tbiQZd/aRQQaX\r\n"	\
"5AdIFCJbPip8ejH9Sv/IW0fns61/bX//bwsCnILXDxmMS2SwBCu77lRTz/zwoXDs\r\n"	\
"d+VgtMkUotsc7Il4Bb1TIRIMLWfyacCmPZqazEcw3DMWxPnJ1lVTNgIlgYbcCOXw\r\n"	\
"4p3JrLC1KKRpHdBI0rsFWUqk10frnl8iB4s69CYIur/Zhr6tOeQYHGl0MqlSK7BB\r\n"	\
"lyFfokTbxWUirl0kCBOk0AEH9NczTxXJoVftJbSnp0pDjFgI+h0NM8cPAInbGqrF\r\n"	\
"tCzBJ4TBAMd6lmDyTIEnwQ01lH8zIwtBp2pGk4I4cB3z78Spt0O6PcUTfrQjMXaj\r\n"	\
"MVVn4MxS2/TC9Mi+MWVcLhTCJKPKz2j26joa3PUUExdy/6yJ2VqbFBMZ8kUzMxik\r\n"	\
"m6x3pQtpyrDaZdCxpuSngHC5iJpba2rZI0RfsYXnJkK9p24Y9ROSvZuWseERAfDe\r\n"	\
"GdjpiAVLHeB4Hv8CIp4CnNLL43SJvPQd1Hqh4N1JsQO89P6B1ObNZYbZTTwF+7Le\r\n"	\
"wCbdC4+kx4j2BK7PZmuCKxM3bdG43VzugRDf59QR1ijd5SKiGSWoaJ0DrrAw7Z5i\r\n"	\
"rKc1EuxozTDD+cVR8uXnhDKuR6GffYRZb9lW5s8OdREI1TnDieEDdCgbti+wkbUa\r\n"	\
"Sb+wm0h6uLVZY3pFqHORwh46asSTTjrwFi98KXKJ1OzD3mUuKR029grwDipDJd2Z\r\n"	\
"dqLMUun2aLl32lPsDTdQXnjsTUN1k4frV/VIX5McuoSjWQgtujJ7l3htrW3kpgI/\r\n"	\
"3sT8tIijgjTKSfm0/bs90E4UobKUihSnjuH6XFClQd/8Hk6RyUDw37yoBoLSS/WV\r\n"	\
"ZUOhuhhvkD2z3M6zt28h86T6zNyhVz3SJ/tTgBv2s/w+gRnlmCOneI+/I5E7ujS+\r\n"	\
"QqXQj59KPnXMM/EgA9OF5OCIMMFP/4w+IR3a49PgKEl8eHzqWOu3lS9qSDELoHGt\r\n"	\
"eiQYLmuhIRChtEpxo25XInLTRxVMHJ6MXmXDrTk6jMcFHr0em6D0We7qTGgAdF3P\r\n"	\
"vtIOuOuutVH8FbW9yf5WRSa4obnmkyPErwgtxzc1tbn8o41us+9OjQbdQ/kLh/Se\r\n"	\
"8zWaihcfMJa1QSrWig4bZFIPJn0UUPWOCTNvmzZjkTGq9w7eSib3R6qzdyiA8yRX\r\n"	\
"NRVijA+kcF62/PgGH8OP0JoDT0TGWPmuwiH+Ji2F3VZ8Jhy8f9yIIzrvPjv3E2Ag\r\n"	\
"upeeSQ+uC2C9oiUei95Qs9xOdIUmBL2LUm+Z99KTJGTvIyamiYIF3I8ROVaFWkgz\r\n"	\
"HidoBN/fg2uldJIn2ISJwUocMiCZVHpjh1Cq9cjZl94QJLT8dE+UXVBzi4lrVHUm\r\n"	\
"4XWKrk5j/MH3QVHzAgmoSjz1PW1wNfxvMLFJGpyt7Rj8GD9BfqfrvPWRC7CSDmQz\r\n"	\
"EaQ0b55S4AKpqAqS9UuX73tACZ2JTMuAAIw8rBDoH1QfscOHYkiF/hBHq4XAvcwU\r\n"	\
"2bD/o3KGDcNmS3UJSEcUx/zPCBxgRE51KkbJbeYDWI3tEjaEGV6Y/xbPO6dQSGDJ\r\n"	\
"gUFHJtePhDkmXcrYLP16S8HJOykq9Psh3PuRNZ+PAkUOfvTaroBUr9dBbo9saCTT\r\n"	\
"yVdrrNv+p3JMrx0z31CBRzo/Ab+RNNVhI4uB1SQkODCSmXosUWsyfT2CTd1OfGY4\r\n"	\
"DEY4XUzKclep3GtdQiCcqBbjTKXWOBn5qPXJwrwhYUCsm7v9+9vRYG056br7h5iH\r\n"	\
"MWLEjqoNZ0XbpPs93Y5uiG7p1YCpBi6V2CkA2IIZ3zd6i9bJ9wsMD0KKM3fjYJjN\r\n"	\
"q4Cpn60HJQI/1iRwEOE9PKA8Zd3xD2+W6lOL83uWCMLTGrsyQA2ebDxB25BDSlet\r\n"	\
"G9Z1jyVK1cBBS7LoPzKeagpVG7Pnbl7bQL3hRzLTHSJ4Qcxy3medBE2Tq03iehEH\r\n"	\
"UpNzdH41N0Kv4gMJg6kgwUeENBs3/ly6LRLg/+4kmI6pQQJcogt7EQ02WhmqJnJq\r\n"	\
"eyuS5OmHH9/Hy/wHLkz8Z5CWtdeyjlFjvrnFiplO2J4JBFJ2bZcOT+/AfcFkLmhM\r\n"	\
"lYfVXyVThIDYkXxXmVnkI04SIOVbIGTzl247qSU3gFa3S7FeaeAZqy5OPLeBAovh\r\n"	\
"kp+kCGTsuyVlq7FIt8uKoUCaExG9TpojV+TTebIAKteia97PAV9Rs3sbW/HgPA6m\r\n"	\
"thdU539mH/64qF9YG2yksknuPQFOTeBSmbTAplDisiKu4zvxW10MClsWVs+JSn/G\r\n"	\
"tXrWE6Q6VhlkjBEuI+syXrDrACnFBKAQMxQWSd5UO7q9SUWW7WUm5011VxBc3n1N\r\n"	\
"bhNwZP5dlrNe77uokcDEkNmo/3DE9RBd3VMeFP+piQHCHhURbu6jsyYSpwzOWqUY\r\n"	\
"jfNOigY/ewFTNcr4P7QXdkna+1ly5jc0Wa6Gq2DnC0u7yyRfPzZwwmD9oYLrvHJw\r\n"	\
"dIC2nF4Ls89gbI7NGGnuXjz6MWvMDWhsqU4EywOVmIzNvrmPWJt7iGu2tCW64Pbx\r\n"	\
"6tYyj/m4e6Lc91yhHFxjWub+y1O85+sLBVe72WgFMwW9EK8DMKgWxSkh2zTUjYRE\r\n"	\
"kakf0P00gYbwfcPFdfoArawfF4+sBxKk987ZFCj7rcH9B/sHsIZX+Chth+rLY6f+\r\n"	\
"4paDUb2IfLMAX4+PhDUFO8HWqD0/uJRJR5oAXF/vqlibCglZgBll2yO0Gq9s0UAc\r\n"	\
"UxtU9E+DQ+TIpqgDRg0FKXSaTLghb9lZH48JRGF4h40Aq6Bc19w22xoDWRle6XTz\r\n"	\
"DLm/UFWsEFOtxcjqjaHLSo2n4rdniyLO+YSy3JeO+Ch/0L0nzLwqG058gxSOQ5qL\r\n"	\
"g1sUbF3I8l8TLGf9V0gQuNzCjART1mUjsu7A16p3qjEgV3lPojKvE6Hyy2SRrE1z\r\n"	\
"oQPZzTPw4vVJY6sG7nd3hxR69UF9zeWThv7m0tqgHxMvOlAZiSpBt/3X2GYx5jcM\r\n"	\
"KnDk/A99JEhjcgk0iZmPgDZK7pq81J+aPODMiRxTlaeQFGs98NYoxz0bTAxv6KOg\r\n"	\
"EUWcy0iYfMdZtQs7YyM4Marm2FrcqhyesOgaMkFxazB6OXRrCtE9yvDdc0ijzFlE\r\n"	\
"Lq/4FPqM+KGGxytqs3CUMand8hY6fMSMM8sfQFMHvEu4tEtBTUSSXNOzBqbKQsZV\r\n"	\
"7czDBAWp8NTYBL3l52ldVFB5oqp+Ksw2BaaFZ1Zmy+lWxhKc5/ac6j820avXw1v7\r\n"	\
"aFChKg2L+GBv5/ksHDCtlJITfOXACPX2R4B9/pETAYeyTMhllDDB217Udmv4v4ld\r\n"	\
"KlU8WoPOTJywtnxtE4HTMuVcXh/4QcatR7RxKmMZpvi+CC49AdgwQCcC3Idh7Tj0\r\n"	\
"yIySBlXbN+i/S6AFTuXiu7y+vYQU5+8jUqBhrPjv5V+Q8FWM5qlueask1AQqnjdC\r\n"	\
"0ksLQ+OfS4PhSoU1W+wWjrsuCiG0Lwc/DoXHmXNBCS0zVjljXBx06WAOBZl7C2Xr\r\n"	\
"kXxseCPQNS/Mjg4EnRT6amdTxF4YuFwVY4IyFYi58PeZeS5LxekdLyYR8eTpD8vC\r\n"	\
"qIElWU3gxQxkVdfNLFAtAyQgLKTgwpagdulYrcMMGEivTEuzK28vIl658K4VJjN/\r\n"	\
"5Ot4QWkkwRC3rSk7utkQ+ZlN7MQqcoC5hIK8+WwuYrpJCWEOxuDoGQ5SHDal9jux\r\n"	\
"OPy3irBMI5jiPR9qnrWIqSvHOE9s78+H/wI2PykbnpFQJtm3TgXWa5p+09HS8m+P\r\n"	\
"7A5NkL+IWJJv10V4Mx/1GCFnR9DCLPkBZ/7DaSsh9CxiuIcHKzTjRqDIutuUyoXI\r\n"	\
"Ay9guDnZJ7p643Urb4mZClPZD1BaQB3zhBj1l8xLyupfwYTt4NV7BKBREm0VrIqJ\r\n"	\
"B4lzbPVIPvW0stoL/Gz/T4eFv5M9nBQ1zB37LZwxD2wJkOjXnRQMB1yf1TRwZCRS\r\n"	\
"hz4CDT30TxuNFaNa/aoHsb8uuD53zEJol1BpFXJb5qw6xW4Urzjqz3kFvKz4/wsi\r\n"	\
"xLN5yjzdkd/1B04u49x6EVk85VvCgUGQg0RbBgpCdSCV3H8fVXhC/z0L7CzTt7vJ\r\n"	\
"1hBYmnl46aB2brn/RcOO06Hs3wUfk2gx+82KebBTE4QSvdrI4weUyidasM/NsyCs\r\n"	\
"UdhDxTYmOSDT9cX4QfeaHmDXyXLSSVG/LRoeeug1Crrx9wr7ny7cMlNxr5PHmSAD\r\n"	\
"X/DFdNx3kSm0sTjPmEBQNkar749CYUUAdkomXZYlMyE9Ibfs43lUv8fRO5C5vbi7\r\n"	\
"Bd887lmU9nWhhaxl13U1XWnZ1hT7/SeLnGIJedxkw6+TNXFIkRMaKpjrJzBg4kLd\r\n"	\
"QQ94W1M6rc9RmdTdnBpbjM8jV//TgnubBiEvLpUmWhzt+++z1G3JqjADSSKVCZNe\r\n"	\
"yowfhikZxgarIEtibDaDzTHk1V2oxuI2dNRkSk3D20w5wTtGvE3ZO4zNd2ziBj8p\r\n"	\
"M+0rJrm5+tnu3MGmyQPvnUcJjWHzUF3QOPEbJgzB2MJtKDyahI/S94fq1vkkRWiB\r\n"	\
"H+5UNBQ99oArt88aOZGcljw2J507h1LtzbbFZ3MN71rziOkHSb5fPor6rFcYMEhE\r\n"	\
"m1a1TXkjTTArnq1N3IfQAHfo2T/egw6mpheOHjaoBXfbaEtFpQWj/nNMb18PwLGJ\r\n"	\
"5njyxtZZ+V2tVda35+9JmcrHw1UfkpISyuN6yKtsFqd2foRif7WJpCrzmlTi42+8\r\n"	\
"YOgQxo9lbpywlNDLBpl169z2Ja7HbGB/9a64+JAPWUYl9aKEJsWQFO1u3rLeQA9r\r\n"	\
"icQs7LMuF0Hv1n2cLBR6rF+8RrJ/u2JjAOfOKiB3gOg7/QlT9NBUK/9cg8hL/Xir\r\n"	\
"YTaV6US3rwpmF7ib/iK9Mss5CL5nvKVgJv6mFFO/06nvo9qDOkjZhQN/4T36Am18\r\n"	\
"l5r7fQsufaeU3/HZxm5nvuBqFyoqPZBpicxz0EbRY9pbMljGtAgvL86pB7/mGamH\r\n"	\
"Epik/hbyk915UQvtIsMV9zcfrsd8kEu3R9h/m7ET50O6Ymg7ix4/SFbr/ULKLsHq\r\n"	\
"fZyE0mAZ+/R/uQQ5VhfA6lIOuT3xvhGcd+DcRZQ1TDHGdBa8p4oIZAsJfy7g7SHZ\r\n"	\
"kjKU+XhJu4If+K3yUJ4U1KCSbQlLRyPzt8kCnXalUV83seOAGp6jaWFeslM3hJBm\r\n"	\
"MEpU77RIC9wEZ0bUhp4MvcGMA57PIo5//khqlSWeSGuXsIB59ZoF9O7zYUMUuihd\r\n"	\
"/anA+iJwBMgWES9YVwhEOnyv1yj98c5k3b9M2q7Hja9zyeov52JBKnZzIfp3rDQ6\r\n"	\
"4qtLdCafITHtfsARrnSNdI9phL/oXG2vUld+6wzzeoEyHOr/e3Xj3C7kiwK6NWRO\r\n"	\
"TRDTqHHrngR8c4DA+K642YZ2P82adcXA/wIszvnZt0JKQuiB3biTIK8YAauCJDiN\r\n"	\
"wQ44r7d8wHUlZ6lRAH7tgSM6reab6ZGEgd6NiBwim3+U0ENuIh9KkkQRqxLDfdTo\r\n"	\
"a/4Xjy0AfBj/D7AOmxv5XB3AKFVSYqHbA57jyZnfieNbYJvsp2Qq3NyqtM7RJ2Ef\r\n"	\
"2rBGyzuqMjhkqAHWU+TRZQb+JyPVzCLbM0R9H1FL8rqXuEh6fXIAYr/8r9nvi0TR\r\n"	\
"IZdqQAr2qtVMIJfOZLgtHNMiaOYulzkzv/UIEOBrhHC3TC++GezgAGL4MxzA3MMM\r\n"	\
"9ntNE51rWKpzAxGxUvpkHtT1KRcKYiyHcAyLcFUYPtEgw9Vabf5Ld6DDufsDxEzI\r\n"	\
"bo1mBYBTji3sn2nQ0rDG9dKJOPMKs3l5Zjqp5BP/bzIcz557QfjNjXRN0SRAfmQB\r\n"	\
"r1fQZCegNQakE2tuLF1GyX524p25dZHhmS4XUd73mPJBHku0tTo+gOIOcv+xF59o\r\n"	\
"wrznRGjWYO4zI9ieHV3GZDR+iS+Frrq+PhpGvG5ku6UtHDAV0+TOVRvBVqVM+kNc\r\n"	\
"2Bi1IJm1sHPywSehaXQO78d49CXVZkrgndCXFTCrmvlyNHPvgij2CyuPo1AZXrRh\r\n"	\
"UDb7Td0YFe6dcrk9CSqt2i/cXRGfoD2Pg1350w6V1S749qw7mr6Lw4gwBdsYCsJs\r\n"	\
"RYnSZ5C3N/GxB6TDXmT9JHFsHcG/HTR1xKOAovRFlk2TbbLFcoQJ+wKwPd9Es7Q+\r\n"	\
"CZIpGpBTw2HYaWK3Tjj3gxRlZpIPvaLOjoH4Z5NOSFYXAaz7PkOl5c9YIo0NAO2I\r\n"	\
"LbNd1uiuaCNq7/O8/SXjiypHkmAU2dVsabHNz7lYHVZfiZ8++nATvsLL9EokKwTf\r\n"	\
"xY2G3uRwtiTYLkpvgn1IJz0gjR4jz4EknUOe6b6xeZGneafRbPPTc8yV0V/gJ0sa\r\n"	\
"W2z7ZGHYH48uW42bQK0MR4ycDzjvbmk8ohwGe8/KqzP56U5JIUoWF2S2ZpCUjCqP\r\n"	\
"8EH54ijQ1eNR2GHLH8rt5G/f4ro2PW3G0BwOwZilDXDbmrmIJHffLGNq+k+MDzBF\r\n"	\
"QbOryvBsawY/YCzf+rTfQETkL1AMTN391Jub0y3xYDIPJBngzdLvSf9LjQs2EUw0\r\n"	\
"wbFwTUdfyBA7q9IdsYUEr284RxRzXblMrFXgAbn5oS2MY1VkUIR7chuMN8OixRxK\r\n"	\
"XPxAg83DWOxsVU1ww0LyzhPN2K+c2cxlfn7vvs6J/qDhq/whrrKRY0w2w30Ixs5y\r\n"	\
"X9ykryazxsiywFYeYNoXs3vhkTrEG8yIX3FrrbvtRGam+THlTyy96kp7PruuuDp8\r\n"	\
"v4MCUKj+J5D18m1pT3izCzRd+XXr9WkLn12GTSiBBR8rWU0nbq5b80DlaevT2Qa4\r\n"	\
"h6c2Smrb9t4cAZEjVq5eqH6Chcg5GsAGBNJBub9SGlFy68fpScZkrPoWPz/Tw14O\r\n"	\
"cyUiBJ7DSRoeBEn16GBwMHQNO2TALE0sMeML0PTcOFOBTdZy3HuqTQleBwotfh/B\r\n"	\
"V1qYoAwu0kRhPWE0MM3GkR0kQ+tOLM3wQLo16D6W+I1vs9z8tvhLpvpDgC3zwNjs\r\n"	\
"XhnuiqgU4nTg0rgsFWGGSE8WzdLOOZOFTZdpWbijiVV0EXUuYvjGbTglWeUNWYI8\r\n"	\
"D+o7OBn4y7YKImYg3F79ssIzXVqzGsutYqYjN8f/3biNhZuQGS7mYDwBEJslqaG3\r\n"	\
"tMQqwCk+tLcndqn46Yz95aPB4nviVOKMZQaVrCNXN2eK8B79pii9q28+zqaK+VsX\r\n"	\
"nfazOC2gU1CtBNkWtXDhp9QvHcqiarSjOKTbHaOjHYK2IKHoXJi17ni7Jm/N7C2v\r\n"	\
"hTNsiXy2Uu8O/RwPbUHS295V4nR6KyNfp4QxJ9tRAkaUl5VClufTKJVDNVQvNgCV\r\n"	\
"hxZJTtyYR9j6tMjTx3KI4ACxLJEoNbSSkeY76KKjvDkdUcVwXZoaFGLRlBD7D3u0\r\n"	\
"304/bMh74a4yWXvGc7t45JFGgespvXanqxDy3Atzts5LXzFrafbfgJT39HszUjgj\r\n"	\
"7dZEQrDVYeceIabzSqKBr+t3NQZQBVV9y3B4gHpUrrM24ZtGGvytz6F8qyYxddvU\r\n"	\
"99nzKRnude8DquAfuvxIVna0mz3rA3bZvmicAG5G376QDkTRmFcJZ75Wj1KuYcIC\r\n"	\
"bdTcEmO5NOMyzv6YZ6pLV/PAZz1IDMzugXSVUE/uzYptxgCKn+253adO2mFqhwEc\r\n"	\
"pr83FbWqSrzZzSXIFPTB1VW4RG7Tt+7uu9POFfqZajicNIDZCWQCB2QBfSbNm4Ro\r\n"	\
"Q6sHwzx81x07zvF8Irf0w8S4eX7+RFGcvIcss3evj9Iz7i/iWtEvJkj8IySjL+XM\r\n"	\
"+ZuX/r3/6wag9I+wskhFseACQPGA90EpSKXV4A+GTKTOp0HvRrQxvZZzLCIokl05\r\n"	\
"gj0AN0BZ90m0bAPqyuoW+NPoLWh48Qgc4v0NBdpQei3DZZAuFxSnL2f5rZNZ2C50\r\n"	\
"Ztn7DUrdsVkQlPxuRiGDNucLZTzYEwowECTOAbkWeTwaWVZyxZ8pGgG9gT1y+4qv\r\n"	\
"2K+O5MLNcHOdOn1nlJnAkQh77K0wqg4beUOqjGoj9PNRSoYTfAx/UZ7u/yldOvJZ\r\n"	\
"3TJ3YN6IKb2MYJth+9toMo+0kmVIL/V4/fwKr5mYboIj72LMXKpyDm8GEo6G4IFp\r\n"	\
"oAqhoi2zMRbmhW1lLMJKk/z2d7wfpJJCiCfNau3fDyRc15iqU4S7KTAng0BnXrbg\r\n"	\
"BVF1lwyKQPBV8LepgRUfPE4SGa1WA6tXf/aoen9WF3uYWPCAa1v9uDybculjkKqK\r\n"	\
"JkEDOKLQxSISweIfY6lq7z76YxOblLHsAx5EMLyLrLstmowh2wlUjbINCUXLmmwX\r\n"	\
"jQ9tgDNgx7AZflgIEdhOAx2al7FEMMMviQ1TMhNbiUES+en9ZOX8r/h2zqG9Fiyi\r\n"	\
"wYgVxtoje+B4FrkeQotACNUBSAPzkXtyyeW7auJ1++tvVRZIS6LT3JOffU6QFDOQ\r\n"	\
"FyPTx6kWI3Ynxxf6GGSE6GiTaTweU0p2gwWVLJ4G8X3kjfPte06TJh2Bkw0Y8gWO\r\n"	\
"dhIYMu8/dJ5VaBtC4HaaS4Vj1iGPNPSgyT9f2wm/Xt9F37Rcjsvr23ydvHTEw0xP\r\n"	\
"PrjEkNfWBvOjIdihJ34wNd7WaS2E9SCT0Sr+h3hLcDhTq1wfZhDDqO509rMx4+l5\r\n"	\
"z82AJNPSU0w8tK6OtDAlSco5W187KuvadPpT5fHGmXIOidybhfkUcqF5/TBNmB76\r\n"	\
"22kGsC/0wShTJiOFuIdyCuwqzAZ0GZrC1RkBzHPZuQgJRNuqVc2HrkfdUbvFhEAp\r\n"	\
"4wBLZD7evvThQx0fm3CqdwZf/LWfKldIezeuG82APsv/Il2LoWQuA0Y2NNroma3y\r\n"	\
"stizGVwlVlMh9C3N/NQjbaDUGlGZLiDRRkT9otd1b/QU2ugBMAYA+2Yoq5yk8iiu\r\n"	\
"6MCvsZRrJUILolXxAjjILgDZfZw1aIRbB67sm4ClU9AdFyaXuYkpsDqFLOQYU5BC\r\n"	\
"6QcSYQcayQlGRxx5cd7S1JEUwyMFO1LZpJhqLIuBq0VAXzN0nEtu3Ucblma+7WMz\r\n"	\
"lyhixsb2YSoic2Ec62UYkTLiZjuj0BSkTXWQizlPV4Zlmhp6J/+lGCuGeu8zeg9j\r\n"	\
"6NRoCPPAaNDCq/5fLiCHdKAeTMwNgALr+kkAzEDEDHgXsdz7hqN+KqDiy5fG7A+L\r\n"	\
"ftUS4o0r7rp1+CQvJ/2OdH5LaEEb5qaR6xSOMRgu68Fv4njw27VmAdd4biHoNF38\r\n"	\
"UtpA059avFIjJf9HuknsTM9i69ZjBw3153w8tDrD/IstrzmN0x4XkfoWwWZnSRDa\r\n"	\
"OfawjiBzCL1JnCjev33mKMXduX1IVGNm1J/NU3Oub4xvXlzrgR9YF7nnJFY6tT3j\r\n"	\
"Ho3Aln6nvQPUqhSjHBBJcZLm1sXeQmXxBOB55Ixl4X/38SZAx3lDoLt+mH6Xgn2E\r\n"	\
"I5ZaNbwUHz+ycZ+n1D9rH1x62WmcOFje2e9y1vXBysh/zVPe1wwtWt12iha2Ywcf\r\n"	\
"93vENnNjh+1c00VhKEoo1Q4NWSEX3+wM4dmr0Gm1WSn5XzCptte0i/YDipeIlSfL\r\n"	\
"r/dIi8AfphZPmRWGakLK0t4KSlBUGJp1tcWer4nPPVuprm02c4XzaTvYLm8xbbsJ\r\n"	\
"g6q4t0enaPyfM7cAjfS89IQLFQN9hjeawI+SBCTolcz5wOyrGF+Iw0xGZFwk4IR1\r\n"	\
"xA/E2FPBZB49aKIsaIZ+sN5UBaloszN1HKVhs+6ecGp20GWZwfvAex5EaN8rYhEn\r\n"	\
"MkqaGyban7OK4llugwAhYsuNHOmJ66njb2XMhxZF5fx+Xp/RDQeyd5RKEE+/6giT\r\n"	\
"TdYJ1kdtX9KccZF5OnFz6Z4sse7dcV6Htck/MyW0J4g+FBw=\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN SPHINCS PRIVATE KEY-----\r\n"	\
"MEwEEQD5O9casZuN2mwaKEzwZu3/BBARHnRVdAkWX87WzeCx9bTuBBBSYtxN3mtQ\r\n"	\
"OoyTVh7UiL7UBBBmdyiOrXfpOtUXI0sFdxqPAgEG\r\n"	\
"-----END SPHINCS PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_CA_CRT_DILITHIUM_SHAKE256_PEM  				\
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM  				\
"-----BEGIN DILITHIUM PRIVATE KEY-----\r\n"	\
"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\r\n"	\
"DX32L+y5MVJdZgl5AIE=\r\n"	\
"-----END DILITHIUM PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM  				\
"-----BEGIN CERTIFICATE-----\r\n"	\
"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\r\n"	\
"dhoAAAAaAAAACgAAANhsCAAYsQ4AGFz3dg==\r\n"	\
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
