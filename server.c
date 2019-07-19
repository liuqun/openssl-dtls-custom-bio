#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"
#include "cbio.h"
#include "server.h"
#include "xsock.h"


int server_hanshake_is_done(server_session_t *p)
{
    return p->is_handshake_accepted;
}

server_session_t * server_session_new(SSL_CTX *ctx)
{
    BIO *bio = NULL;
    struct _server_session_t *p = NULL;

    p = (server_session_t *)calloc(1, sizeof(server_session_t));

    p->data.txaddr_buf.cap = p->data.txaddr_buf.len = sizeof(struct sockaddr_storage);
    memset(&p->data.txaddr_storage, 0x00, sizeof(struct sockaddr_storage));
    deque_init(&(p->data.rxqueue));
    p->data.peekmode = 0;

    xsock_t *xsock = &(p->data.xsock);
    xsock_erase_host_ids(xsock);
    p->data.head.cap = XFS_XUDP_LAYER_HEADER_LENGTH;
    p->data.head.len = p->data.head.cap;

    bio = BIO_new(BIO_s_custom());
    BIO_set_data(bio, (void *)&p->data);
    BIO_set_init(bio, 1);
    p->ssl = SSL_new(ctx);
    SSL_set_bio(p->ssl, bio, bio);

    return p;
}

void server_session_free(server_session_t **pp)
{
    server_session_t *p = NULL;

    p = *pp;
    SSL_free(p->ssl);

#if 1 // for debugging
    p->ssl = NULL;
#endif

    /* Don't use deque_deinit()/deque_free() method to clean up the rxqueue. Use the following steps instead: */
    deque_t *dp = &(p->data.rxqueue);
    while (deque_count(dp) > 0)
    {
        free(deque_peek(dp));
        (void) deque_pop(dp);
    }

    free(p);
    *pp = NULL;
}

void server_append_incoming_packet(server_session_t *p, buffer_t *packet)
{
    deque_append(&(p->data.rxqueue), packet);
}

int server_decrypt_incoming_packet(server_session_t *p, void *decrypted_plaintext_buf, size_t buf_max_bytes)
{
    size_t decrypted=0;
    int ret;

    if ((ret = SSL_read(p->ssl, decrypted_plaintext_buf, buf_max_bytes)) < 0)
    {
        int e = SSL_get_error(p->ssl, ret);
        if (SSL_ERROR_SSL == e)
        {
            fprintf(stderr, "SSL_ERROR_SSL!\n");
            ERR_print_errors_fp(stderr);
        }
        return 0; // 失败时: 返回 0 表示失败 (当心: 即使ret<0, 函数server_get()仍返回0)
    }
    return ret; // 成功时: 返回值大于 0 且小于等于 buf_max_bytes, 表示输出数据有效字节数.
}

void server_try_accepting_handshake(server_session_t *p)
{
    if (p->is_handshake_accepted)
    {
        return;
    }

    if (SSL_accept(p->ssl) != 1)
    {
        p->is_handshake_accepted = 0;
        return;
    }

    dump_addr(&p->data.txaddr, "user connected: ");
    p->is_handshake_accepted = 1;
    return;
}

void server_encrypt_and_send(server_session_t *p, const void *plaintext_buf, size_t buf_size)
{
    (void) SSL_write(p->ssl, plaintext_buf, (int)buf_size);
}
