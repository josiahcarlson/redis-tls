
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

#include "ssl_hiredis.h"

#include "hiredis.h"

#if !SKIP_SSL_EVERYTHING

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sds.h"

/* Global SSL context */
SSL_CTX *ctx;

void ssl_wrap_socket(redisContext *c);

static int SSL_IS_INIT = 0;

void die(const char *msg) {
    printf("\n");
    fflush(NULL);
    ERR_print_errors_fp(stdout);
    if (errno != 0) perror(msg);
    else printf(msg);
    exit(1);
}
#define SSL_OPTION_FLAGS (SSL_OP_SINGLE_DH_USE|SSL_OP_CIPHER_SERVER_PREFERENCE|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1)

static int had_certfile = 0;

void hiredis_ssl_init(const char * certfile, const char* keyfile) {
    if (!SSL_IS_INIT) {
        /* SSL library initialisation */
        had_certfile = certfile != NULL;
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        /* create the SSL context */
        ctx = SSL_CTX_new(TLS_method());
        if (!ctx ||
            !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
            !SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) {
            die("SSL_CTX_new()");
        }

        /* Load certificate, private key files, and check consistency */
        if (certfile) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            if (SSL_CTX_load_verify_locations(ctx, certfile, NULL) != 1) {
                die("SSL_CTX_load_verify_locations failed");
            }
            if (keyfile != NULL) {
                if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
                    die("SSL_CTX_use_PrivateKey_file failed");
                }

                /* Make sure the key and certificate file match. */
                if (SSL_CTX_check_private_key(ctx) != 0) {
                    die("SSL_CTX_check_private_key failed");
                }
            }
        }
        SSL_CTX_set_options(ctx, SSL_OPTION_FLAGS);
        SSL_IS_INIT = 1;
    }
}

#define SSL_CIPHER_LIST "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!eNULL:!LOW:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:!ADH:!IDEA"

struct ssl_client* ssl_client_init(void* priv,
                     int (*io_on_read)(void*, struct ssl_client*, char *, size_t),
                     int fd,
                     enum ssl_mode mode) {

    /* initialize if not initialized */
    hiredis_ssl_init(NULL, NULL);

    struct ssl_client *p = (struct ssl_client *)malloc(sizeof(struct ssl_client));
    memset((void*)p, 0, sizeof(struct ssl_client));

    p->fd = fd;

    p->rbio = BIO_new(BIO_s_mem());
    if (!p->rbio) goto err1;

    p->wbio = BIO_new(BIO_s_mem());
    if (!p->wbio) goto err2;

    p->ssl = SSL_new(ctx);
    if (!p->ssl) goto err3;

    if (mode == SSLMODE_SERVER) {
        SSL_set_accept_state(p->ssl);    /* ssl server mode */
    } else if (mode == SSLMODE_CLIENT) {
        SSL_set_connect_state(p->ssl); /* ssl client mode */
    }

    if (!SSL_set_options(p->ssl, SSL_OPTION_FLAGS)) goto err4;
#ifdef USING_LIBRESSL
    if (!SSL_set_min_proto_version(p->ssl, TLS1_2_VERSION)) goto err4;
#endif
    if (mode == SSLMODE_SERVER && !SSL_set_cipher_list(p->ssl, SSL_CIPHER_LIST)) goto err4;

    SSL_set_bio(p->ssl, p->rbio, p->wbio);

    p->handshake_done = 0;
    p->priv = priv;
    p->io_on_read = io_on_read;
    return p;

err4:
    SSL_free(p->ssl);
err3:
    BIO_free(p->wbio);
err2:
    BIO_free(p->rbio);
err1:
    free(p);
    ERR_print_errors_fp((FILE*)stderr);
    return NULL;
}

void ssl_wrap_socket(redisContext *c) {
    c->ssl = ssl_client_init(c, redis_ssl_got_read, c->fd, SSLMODE_CLIENT);
    if (c->ssl) {
        c->ssl->write_buf = sdsempty();
        c->ssl->encrypt_buf = sdsempty();
        hiredis_ssl_do_handshake(c->ssl);
    }
}

void ssl_client_cleanup(struct ssl_client *p) {
    /* clears buffers */
    SSL_free(p->ssl);     /* free the SSL object and its BIO's */
    if (SSL_CLEAR_BUFFERS) memset((void*)p->write_buf, 0, sdslen(p->write_buf));
    sdsfree(p->write_buf);
    if (SSL_CLEAR_BUFFERS) memset((void*)p->encrypt_buf, 0, sdslen(p->encrypt_buf));
    sdsfree(p->encrypt_buf);
    free(p);
}

int ssl_client_want_write(struct ssl_client *c) {
    return (sdslen(c->write_buf) > 0) || !c->handshake_done;
}

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */

enum sslstatus ssl_getstatus(SSL* ssl, int n) {
    switch (SSL_get_error(ssl, n))
    {
        case SSL_ERROR_NONE:
            return SSLSTATUS_OK;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            return SSLSTATUS_WANT_IO;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        default:
            return SSLSTATUS_FAIL;
    }
}

/* Handle request to send unencrypted data to the SSL. All we do here is just
 * queue the data into the encrypt_buf for later processing by the SSL
 * object. */
void ssl_buffer_unencrypted(struct ssl_client *c, char *buf, size_t len, int clear) {
    /* clears buffers */
    c->encrypt_buf = sdscatlen(c->encrypt_buf, buf, len);
    if (clear) {
        memset((void*)buf, 0, len);
    }
}

/* Queue encrypted bytes. Should only be used when the SSL object has requested
 * a write operation, or when we're pumping data from the SSL object into the
 * outgoing buffer via the "OUTGOING_SSL_TO_BUF()" macro below. */
void ssl_buffer_encrypted(struct ssl_client *c, char *buf, size_t len) {
    /* clears buffers */
    c->write_buf = sdscatlen(c->write_buf, buf, len);
    if (SSL_CLEAR_BUFFERS) memset((void*)buf, 0, len);
}

#define OUTGOING_SSL_TO_BUF(RETURN) do { \
        n = BIO_read(c->wbio, buf, sizeof(buf)); \
        if (n > 0) \
            ssl_buffer_encrypted(c, buf, n); \
        else if (!BIO_should_retry(c->wbio)) \
            return RETURN; \
    } while (n>0)

enum sslstatus hiredis_ssl_do_handshake(struct ssl_client *c) {
    char buf[DEFAULT_BUF_SIZE];
    enum sslstatus status;

    if (!c->ssl) {
        return SSLSTATUS_FAIL;
    }

    int n = SSL_do_handshake(c->ssl);
    status = ssl_getstatus(c->ssl, n);

    /* Did SSL request to write bytes? */
    if (status == SSLSTATUS_WANT_IO) {
        /* called functions clear buffers */
        OUTGOING_SSL_TO_BUF(SSLSTATUS_FAIL);
    }

    return status;
}

/* Feed data into the Redis client after we get unencrypted bytes out of the SSL
 * object. Can be overidden, which is why this is slightly more generic than it
 * technically *needs* to be. */
int redis_ssl_got_read(void* vc, struct ssl_client* ssl, char *buf, size_t len) {
    /* clears buffers */
    // UNUSED(ssl);
    redisContext *c = (redisContext *)vc;
    int ret = 0;
    if (redisReaderFeed(c->reader,buf,len) != REDIS_OK) {
        ret = -1;
    }
    if (SSL_CLEAR_BUFFERS) memset((void*)buf, 0, len);
    return ret;
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
 * SSL object to be unencrypted. On success, returns 0, on SSL error -1. */
int ssl_on_read_cb(struct ssl_client *c, char* src, size_t len) {
    /* clears buffers */
    char buf[DEFAULT_BUF_SIZE];
    enum sslstatus status;
    int n = 0, once = len == 0;

    while (len > 0 || once) {
        once = 0;
        if (len) {
            n = BIO_write(c->rbio, src, len);
            if (SSL_CLEAR_BUFFERS) memset((void*)src, 0, len);
            if (n <= 0) {
                return -1; /* assume bio write failure is unrecoverable */
            }
        }

        src += n;
        len -= n;

        if (!SSL_is_init_finished(c->ssl)) {
            if (hiredis_ssl_do_handshake(c) == SSLSTATUS_FAIL) {
                return -1;
            }
            if (!SSL_is_init_finished(c->ssl)) {
                return 0;
            }
        }

        if (!c->handshake_done) {
            if (had_certfile && SSL_get_verify_result(c->ssl) != X509_V_OK) {
                die("certificate verification failed");
            }
        }
        c->handshake_done = 1;

        /* The encrypted data is now in the input bio so now we can perform actual
         * read of unencrypted data. */

        do {
            n = SSL_read(c->ssl, buf, sizeof(buf));
            if (n > 0) {
                /* clears buffers */
                if (c->io_on_read(c->priv, c, buf, (size_t)n) == -1) {
                    return -1;
                }
            }
        } while (n > 0);

        status = ssl_getstatus(c->ssl, n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
         * renegotiation. */
        if (status == SSLSTATUS_WANT_IO) {
            /* clears buffers */
            OUTGOING_SSL_TO_BUF(-1);
        }

        if (status == SSLSTATUS_FAIL) {
            return -1;
        }
    }

    return 0;
}

void _ssl_consume_buf(sds* buf, size_t len) {
    /* clears buffers */
    size_t olen = sdslen(*buf);
    if (len < olen) {
        sdsrange(*buf, len, -1);
        /* clear right end range */
        if (SSL_CLEAR_BUFFERS) memset((void*)(*buf + olen - len), 0, len);
    } else {
        sdsrange(*buf, 1, 0);
        /* clear right end range */
        memset((void*)(*buf), 0, olen);
        if (sdsalloc(*buf) > 16384) {
            /* free large buffers after use */
            sdsfree(*buf);
            *buf = sdsempty();
        }
    }
}

/* Process outbound unencrypted data that is waiting to be encrypted. The
 * waiting data resides in encrypt_buf. It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int ssl_do_encrypt(struct ssl_client *c) {
    char buf[DEFAULT_BUF_SIZE]; /* for OUTGOING_SSL_TO_BUF() */
    enum sslstatus status;

    if (!SSL_is_init_finished(c->ssl)) {
        /* we don't want to force data through while we're still in the middle
         * of a handshake. Who knows what kinds of shenanigans might happen :P
         */
        return 0;
    }

    /* be explicit, in case we *just* got here */
    c->handshake_done = 1;

    while (sdslen(c->encrypt_buf) > 0) {
        int n = SSL_write(c->ssl, c->encrypt_buf, sdslen(c->encrypt_buf));
        status = ssl_getstatus(c->ssl, n);

        if (n > 0) {
            /* clears buffers */
            _ssl_consume_buf(&c->encrypt_buf, n);

            /* take the output of the SSL object and queue it for socket write,
             * returning -1 on internal SSL failure. */
            /* clears buffers */
            OUTGOING_SSL_TO_BUF(-1);
        }

        if (status == SSLSTATUS_FAIL) {
            return -1;
        }

        if (n==0) {
            break;
        }
    }
    return 0;
}

/* Read encrypted bytes from socket, passing them through to the proper callback
 * after read. */
int ssl_do_sock_read(struct ssl_client *c, int zero_bad) {
    char buf[DEFAULT_BUF_SIZE];
    ssize_t n = read(c->fd, buf, sizeof(buf));

    if (n > 0) {
        /* clears buffers */
        return ssl_on_read_cb(c, buf, (size_t)n);
    } else if ((n < 0) || zero_bad) {
        return -1;
    } else {
        return 0;
    }
}

/* Write encrypted bytes to the socket. */
int ssl_do_sock_write(struct ssl_client *c, int zero_bad) {
    ssize_t n = write(c->fd, c->write_buf, sdslen(c->write_buf));
    if (n > 0) {
        /* clears buffers */
        _ssl_consume_buf(&c->write_buf, n);
        return 0;
    } else if ((n < 0) || zero_bad) {
        return -1;
    } else {
        return 0;
    }
}

#endif
