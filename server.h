#pragma once

#ifdef __cplusplus
#error // TODO: server.h will support C++ later, fixme if anyone is going to use C++...
#endif

#include "cbio.h"

typedef struct _server_session_t server_session_t;

struct _server_session_t
{
    custom_bio_data_t data;
    SSL *ssl;

    int is_handshake_accepted;
};

extern server_session_t * server_session_new(SSL_CTX *ctx);
extern               void server_session_free(server_session_t **pp);

extern void server_try_accepting_handshake(server_session_t *p);
extern  int server_hanshake_is_done(server_session_t *p);

extern void server_append_incoming_packet(server_session_t *p, buffer_t *packet);
extern int server_decrypt_incoming_packet(server_session_t *p, void *out_plaintext_buf, size_t out_buf_max_bytes);
extern void server_encrypt_and_send(server_session_t *p, const void *in_plaintext_buf, size_t buf_size);
