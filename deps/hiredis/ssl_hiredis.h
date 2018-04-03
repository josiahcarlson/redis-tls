
/*
 * Some SSL portions originally named common.h, from:
 * https://github.com/darrenjs/openssl_examples
 * Downloaded 2/20/2018, included, and heavily modified thereafter by Josiah
 * Carlson.
 *
 * Copyright (c) 2017, Darren Smith <github user darrenjs, email not found>
 * Copyright (c) 2018, Josiah Carlson <josiah dot carlson at gmail dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */


#ifndef __HIREDIS_SSL_H
#define __HIREDIS_SSL_H

#ifndef SKIP_SSL_EVERYTHING
#define SKIP_SSL_EVERYTHING 0
#endif

#if !SKIP_SSL_EVERYTHING

#ifdef __cplusplus
extern "C" {
#endif

/*-------------------------- necessary SSL headers ---------------------------*/

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "sds.h"

#define SSL_CLEAR_BUFFERS 1

#define DEFAULT_BUF_SIZE 16384

/* An instance of this object is created each time a client connection is
 * created. It stores the client file descriptor, the SSL objects, and data
 * which is waiting to be either written to socket or encrypted. */
struct ssl_client
{
    int fd;

    SSL *ssl;

    BIO *rbio; /* SSL reads from, we write to. */
    BIO *wbio; /* SSL writes to, we read from. */

    /* Bytes waiting to be written to socket. This is data that has been generated
     * by the SSL object, either due to encryption of user input, or, writes
     * required due to peer-requested SSL renegotiation. */
    sds write_buf;

    /* Bytes waiting to be encrypted by the SSL object. */
    sds encrypt_buf;

    int handshake_done;

    void* priv;

    /* Method to invoke when unencrypted bytes are available. */
    int (*io_on_read)(void* priv, struct ssl_client* ssl, char *buf, size_t len);
} sslclient;

enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

/* This enum contols whether the SSL connection needs to initiate the SSL
 * handshake. */
enum ssl_mode { SSLMODE_SERVER, SSLMODE_CLIENT };

void die(const char *msg);
void hiredis_ssl_init(const char * certfile, const char* keyfile);
struct ssl_client* ssl_client_init(void* priv,
                     int (*io_on_read)(void*, struct ssl_client*, char *, size_t),
                     int fd,
                     enum ssl_mode mode);
void ssl_client_cleanup(struct ssl_client *p);
int ssl_client_want_write(struct ssl_client *c);
// weird name to not overlap with redis-server linking
enum sslstatus ssl_getstatus(SSL* ssl, int n);
void ssl_buffer_unencrypted(struct ssl_client *c, char *buf, size_t len, int clear);
void ssl_buffer_encrypted(struct ssl_client *c, char *buf, size_t len);
enum sslstatus hiredis_ssl_do_handshake(struct ssl_client *c);
int ssl_on_read_cb(struct ssl_client *c, char* src, size_t len);
int ssl_do_encrypt(struct ssl_client *c);
int ssl_do_sock_read(struct ssl_client *c, int zero_bad);
int ssl_do_sock_write(struct ssl_client *c, int zero_bad);
void _ssl_consume_buf(sds* buf, size_t len);

int redis_ssl_got_read(void* vc, struct ssl_client* ssl, char *buf, size_t len);

/*-------------------------- end ssl header/defines --------------------------*/

#ifdef __cplusplus
}
#endif

#endif
#endif
