/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2014
 * Copyright (C) Idan Freiberg 2013-2014
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(SSL_CALLS_H)
#define SSL_CALLS_H

#include "arch.h"

/* Incomplete types */
struct ssl_tls;
struct trans;

int
ssl_init(void);
int
ssl_finish(void);
/**
 * Sets a log file for recording TLS pre-master secrets
 *
 * @param filename Filename to log secrets in
 * @return != 0 if the log was successfully set
 */
int
ssl_set_pre_master_secret_logfile(const char *filename);
void *
ssl_rc4_info_create(void);
void
ssl_rc4_info_delete(void *rc4_info);
void
ssl_rc4_set_key(void *rc4_info, const char *key, int len);
void
ssl_rc4_crypt(void *rc4_info, char *data, int len);
void *
ssl_sha1_info_create(void);
void
ssl_sha1_info_delete(void *sha1_info);
void
ssl_sha1_clear(void *sha1_info);
void
ssl_sha1_transform(void *sha1_info, const char *data, int len);
void
ssl_sha1_complete(void *sha1_info, char *data);
void *
ssl_md5_info_create(void);
void
ssl_md5_info_delete(void *md5_info);
void
ssl_md5_clear(void *md5_info);
void
ssl_md5_transform(void *md5_info, const char *data, int len);
void
ssl_md5_complete(void *md5_info, char *data);
void *
ssl_des3_encrypt_info_create(const char *key, const char *ivec);
void *
ssl_des3_decrypt_info_create(const char *key, const char *ivec);
void
ssl_des3_info_delete(void *des3);
int
ssl_des3_encrypt(void *des3, int length, const char *in_data, char *out_data);
int
ssl_des3_decrypt(void *des3, int length, const char *in_data, char *out_data);
void *
ssl_hmac_info_create(void);
void
ssl_hmac_info_delete(void *hmac);
void
ssl_hmac_sha1_init(void *hmac, const char *data, int len);
void
ssl_hmac_transform(void *hmac, const char *data, int len);
void
ssl_hmac_complete(void *hmac, char *data, int len);
int
ssl_mod_exp(char *out, int out_len, const char *in, int in_len,
            const char *mod, int mod_len, const char *exp, int exp_len);
int
ssl_gen_key_xrdp1(int key_size_in_bits, const char *exp, int exp_len,
                  char *mod, int mod_len, char *pri, int pri_len);

/* xrdp_tls.c */
struct ssl_tls *
ssl_tls_create(struct trans *trans, const char *key, const char *cert);
int
ssl_tls_accept(struct ssl_tls *self, long ssl_protocols,
               const char *tls_ciphers,
               int (*is_term)(void));
int
ssl_tls_disconnect(struct ssl_tls *self);
void
ssl_tls_delete(struct ssl_tls *self);
int
ssl_tls_read(struct ssl_tls *tls, char *data, int length);
int
ssl_tls_write(struct ssl_tls *tls, const char *data, int length);
int
ssl_tls_can_recv(struct ssl_tls *tls, int sck, int millis);
const char *
ssl_get_version(const struct ssl_tls *ssl);
const char *
ssl_get_cipher_name(const struct ssl_tls *ssl);
int
ssl_get_protocols_from_string(const char *str, long *ssl_protocols);
const char *
get_openssl_version(void);
tintptr
ssl_get_rwo(const struct ssl_tls *ssl);

/**
 * Extract the Common Name (CN) from the subject of a DER-encoded
 * X.509 certificate
 *
 * @param cert_der DER-encoded certificate data
 * @param cert_len Length of the DER-encoded certificate data
 * @param cn Buffer to receive the CN string (null-terminated)
 * @param cn_len Size of the cn buffer
 * @return 0 on success, 1 on error
 */
int
ssl_cert_get_subject_cn(const unsigned char *cert_der, int cert_len,
                        char *cn, int cn_len);

/**
 * Extract the UPN (User Principal Name) from the Subject Alternative
 * Name extension of a DER-encoded X.509 certificate
 *
 * Looks for a Microsoft UPN otherName (OID 1.3.6.1.4.1.311.20.2.3)
 * in the SAN extension. Falls back to an rfc822Name (email) entry
 * if no UPN otherName is found.
 *
 * @param cert_der DER-encoded certificate data
 * @param cert_len Length of the DER-encoded certificate data
 * @param upn Buffer to receive the UPN string (null-terminated)
 * @param upn_len Size of the upn buffer
 * @return 0 on success, 1 on error
 */
int
ssl_cert_get_san_upn(const unsigned char *cert_der, int cert_len,
                     char *upn, int upn_len);

/**
 * Verify a DER-encoded X.509 certificate against a CA certificate
 * store
 *
 * @param cert_der DER-encoded certificate data
 * @param cert_len Length of the DER-encoded certificate data
 * @param ca_cert_file Path to a file containing trusted CA
 *                     certificates in PEM format, or NULL
 * @param ca_cert_dir Path to a directory containing trusted CA
 *                    certificates, or NULL
 * @return 0 on success (certificate is valid), 1 on error
 */
int
ssl_cert_verify(const unsigned char *cert_der, int cert_len,
                const char *ca_cert_file, const char *ca_cert_dir);

#endif
