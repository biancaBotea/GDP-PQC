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
"MIJFdDCCAqGgAwIBAgIBFDAIBgYrzg8GBwQwgZYxCzAJBgNVBAYTAkNBMQswCQYD\r\n"	\
"VQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xFTATBgNVBAoMDHdvbGZTU0wgSW5j\r\n"	\
"LjEUMBIGA1UECwwLRW5naW5lZXJpbmcxGTAXBgNVBAMMEFJvb3QgQ2VydGlmaWNh\r\n"	\
"dGUxHzAdBgkqhkiG9w0BCQEWEHJvb3RAd29sZnNzbC5jb20wHhcNMjIxMDI3MTAw\r\n"	\
"NzI4WhcNMjMxMDI3MTAwNzI4WjCBljELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9O\r\n"	\
"MREwDwYDVQQHDAhXYXRlcmxvbzEVMBMGA1UECgwMd29sZlNTTCBJbmMuMRQwEgYD\r\n"	\
"VQQLDAtFbmdpbmVlcmluZzEZMBcGA1UEAwwQUm9vdCBDZXJ0aWZpY2F0ZTEfMB0G\r\n"	\
"CSqGSIb3DQEJARYQcm9vdEB3b2xmc3NsLmNvbTAtMAgGBivODwYHBAMhACqn/3K3\r\n"	\
"dSyLKuiQ+rFu/93Q1rTKAo9L64E3QTPGvbXeo4IBCjCCAQYwHQYDVR0OBBYEFFXw\r\n"	\
"vYJqHf6itjdwNvNjc28kxec7MIHDBgNVHSMEgbswgbiAFFXwvYJqHf6itjdwNvNj\r\n"	\
"c28kxec7oYGcpIGZMIGWMQswCQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNV\r\n"	\
"BAcMCFdhdGVybG9vMRUwEwYDVQQKDAx3b2xmU1NMIEluYy4xFDASBgNVBAsMC0Vu\r\n"	\
"Z2luZWVyaW5nMRkwFwYDVQQDDBBSb290IENlcnRpZmljYXRlMR8wHQYJKoZIhvcN\r\n"	\
"AQkBFhByb290QHdvbGZzc2wuY29tggEUMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMB\r\n"	\
"Af8EBTADAQH/MAgGBivODwYHBAOCQsEAFvlC+aubIWmWDBqpRj26sXmNUsse4FOk\r\n"	\
"LhIn8zx6xZDy0UkMa/KwdZj0gLEmt5DBSfx6Dglv9hCskoaY5aHutreTauI6HIyr\r\n"	\
"piqbZyvm5rXnXWUHCB21ZnMAQIhotJTCGg9DQq8gQ8Blw01rCQq7dP1qiCWIbRYw\r\n"	\
"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\r\n"	\
"oMF0LIriIL9tmP16fxwXUyeS0cU2/nNX\r\n"	\
"-----END CERTIFICATE-----\r\n"

#define TEST_SRV_KEY_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN PRIVATE KEY-----\r\n"	\
"MHECAQAwCAYGK84PBgcEBGIEYLWIiQQ4z/BH7WKgBUI4Tl6sCSrcc5/q4PR2lLfl\r\n"	\
"RpWqdnxkgg0LgDw26XcZp774xQVie/VtbucmGDVkzAAL/z12fGSCDQuAPDbpdxmn\r\n"	\
"vvjFBWJ79W1u5yYYNWTMAAv/PQ==\r\n"	\
"-----END PRIVATE KEY-----\r\n"

#define TEST_SRV_CRT_SPHINCS_SHAKE256_PEM                               \
"-----BEGIN CERTIFICATE-----\r\n"	\
"MIJFqDCCAtWgAwIBAgIBFTAIBgYrzg8GBwQwgZYxCzAJBgNVBAYTAkNBMQswCQYD\r\n"	\
"VQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xFTATBgNVBAoMDHdvbGZTU0wgSW5j\r\n"	\
"LjEUMBIGA1UECwwLRW5naW5lZXJpbmcxGTAXBgNVBAMMEFJvb3QgQ2VydGlmaWNh\r\n"	\
"dGUxHzAdBgkqhkiG9w0BCQEWEHJvb3RAd29sZnNzbC5jb20wHhcNMjIxMDI3MTAw\r\n"	\
"NzI5WhcNMjMxMDI3MTAwNzI5WjCBmjELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9O\r\n"	\
"MREwDwYDVQQHDAhXYXRlcmxvbzEVMBMGA1UECgwMd29sZlNTTCBJbmMuMRQwEgYD\r\n"	\
"VQQLDAtFbmdpbmVlcmluZzEbMBkGA1UEAwwSRW50aXR5IENlcnRpZmljYXRlMSEw\r\n"	\
"HwYJKoZIhvcNAQkBFhJlbnRpdHlAd29sZnNzbC5jb20wLTAIBgYrzg8GBwQDIQB2\r\n"	\
"fGSCDQuAPDbpdxmnvvjFBWJ79W1u5yYYNWTMAAv/PaOCATowggE2MA8GA1UdEQQI\r\n"	\
"MAaHBH8AAAEwHQYDVR0OBBYEFFORumLD5oPpVYdy0elC/A3eeYZnMIHDBgNVHSME\r\n"	\
"gbswgbiAFFXwvYJqHf6itjdwNvNjc28kxec7oYGcpIGZMIGWMQswCQYDVQQGEwJD\r\n"	\
"QTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMRUwEwYDVQQKDAx3b2xm\r\n"	\
"U1NMIEluYy4xFDASBgNVBAsMC0VuZ2luZWVyaW5nMRkwFwYDVQQDDBBSb290IENl\r\n"	\
"cnRpZmljYXRlMR8wHQYJKoZIhvcNAQkBFhByb290QHdvbGZzc2wuY29tggEUMA4G\r\n"	\
"A1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\r\n"	\
"DAYDVR0TAQH/BAIwADAIBgYrzg8GBwQDgkLBADqcMkCqz5qcBhuH+Xy2qB/jWn03\r\n"	\
"p5SWeurQz4sAhmXzfgZBA/SJA0bSW/JFwWj3TqLUfPsmPHZj5FJzojSb9b1t+wd0\r\n"	\
"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\r\n"	\
"4U1pMaDBdCyK4iC/bZj9en8cF1MnktHFNv5zVw==\r\n"	\
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
