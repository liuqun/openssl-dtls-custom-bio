#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"
#include "cbio.h"

char SERVER_HINTS[] =
    "My server supports the following commands:\n"
    "  1. ping returns pong\n"
    "  2. echo <some text> returns <some text>\n"
    "  3. whoami returns client's address and port seen by server\n"
    "  4. stats returns a list of server currently serving clients\n"
    "  5. bc <some text> broadcast <some text> to all clients\n"
    "You may try these commands youself and see how they work.\n"
    "Good luck!\n";
const int SERVER_HINTS_LEN = sizeof(SERVER_HINTS) - 1;

enum
{
    TIME_OUT = 8000 // ms
};

typedef struct _server_session_t server_session_t;

typedef void (*session_callback_fn_t)(server_session_t *session, void *extra_arg);

struct _server_session_t
{
    custom_bio_data_t data;
    SSL *ssl;

    int is_handshake_accepted;
    struct {
        session_callback_fn_t on_handshake_accepted_cb;
        void *on_handshake_accepted_extra_arg;
    };
};

int server_hanshake_is_done(server_session_t *p)
{
    return p->is_handshake_accepted;
}

void server_send_greetings_to_client(server_session_t *p, void *extra_greeting_arg)
{
    const char *DefaultGreetingMsg = "(Server greeting message is empty by default...)\n";
    const char *msg = (const char *)extra_greeting_arg;
    size_t n=0;

    if (!msg || (n=strlen(msg)) <= 0)
    {
        n = strlen(DefaultGreetingMsg);
        msg = DefaultGreetingMsg;
    }
    SSL_write(p->ssl, msg, n);
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

    bio = BIO_new(BIO_s_custom());
    BIO_set_data(bio, (void *)&p->data);
    BIO_set_init(bio, 1);
    p->ssl = SSL_new(ctx);
    SSL_set_bio(p->ssl, bio, bio);

    p->is_handshake_accepted = 0;
    p->on_handshake_accepted_cb = server_send_greetings_to_client;
    p->on_handshake_accepted_extra_arg = SERVER_HINTS;

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

int server_decrypt_incomming_packet(server_session_t *p, void *out_plaintext_buf, size_t out_buf_max_bytes)
{
    size_t decrypted=0;
    int ret;

    if ((ret = SSL_read(p->ssl, out_plaintext_buf, out_buf_max_bytes)) < 0)
    {
        int e = SSL_get_error(p->ssl, ret);
        if (SSL_ERROR_SSL == e)
        {
            fprintf(stderr, "SSL_ERROR_SSL!\n");
            ERR_print_errors_fp(stderr);
        }
        return 0; // 失败时: 返回 0 表示失败 (当心: 即使ret<0, 函数server_get()仍返回0)
    }
    return ret; // 成功时: 返回值大于 0 且小于等于 out_buf_max_bytes, 表示输出数据有效字节数.
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
    if (p->on_handshake_accepted_cb)
    {
        p->on_handshake_accepted_cb(p, p->on_handshake_accepted_extra_arg);
    }
    return;
}

void server_encrypt_and_send(server_session_t *p, const void *in_plaintext_block, size_t blocksize)
{
    SSL_write(p->ssl, in_plaintext_block, (int)blocksize);
}

char cookie_str[] = "BISCUIT!";

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memmove(cookie, cookie_str, sizeof(cookie_str)-1);
    *cookie_len = sizeof(cookie_str)-1;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return sizeof(cookie_str)-1==cookie_len && memcmp(cookie, cookie_str, sizeof(cookie_str)-1)==0;
}

void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "Interrupt from keyboard\n");
    else
        fprintf(stderr, "unknown signal[%d]\n", sig);
    fflush(stderr);
}

typedef struct hashtable_s {
    int (*hash)(buffer_t *bp);
    int nbucket;
    deque_t bucket[];
} hashtable_t;

typedef struct ht_node_s {
    buffer_t *key;
    void *value;
} ht_node_t;

hashtable_t *ht256_new(void);
void ht_reset(hashtable_t *htp);
void ht_free(hashtable_t *htp);
void *ht_search(hashtable_t *htp, buffer_t *key);
void *ht_insert(hashtable_t *htp, buffer_t *key, void *value);
int ht_delete(hashtable_t *htp, buffer_t *key);

#define HT_FOREACH(htnp, htp) \
for (int _tmp_index=0; _tmp_index<(htp)->nbucket; ++_tmp_index) \
    for (deque_item_t *_tmp_item=((htp)->bucket[_tmp_index].head); _tmp_item; _tmp_item=_tmp_item->next) \
        for (ht_node_t *(htnp)=(ht_node_t *)_tmp_item->p; htnp; htnp=NULL)


int main(int argc, char **argv)
{
    int bind_error;
    int ret;

    if (argc<=1)
    {
        fputs("usage:\n"
        "  server 127.0.0.1:1234\n"
        "  server 0.0.0.0:1234\n"
        "  server [::1]:1234\n"
        "  server [::]:1234\n"
        "  server [::]:1234 127.0.0.1:1234\n", stderr);

        exit(0);
    }

    deque_t *addrlist = deque_new();
    for (int i=1; i<argc; ++i)
    {
        fputs(argv[i], stderr);
        fputc('\n', stderr);

        buffer_t *bp;
        char *c;
        int port;

        if (argv[i][0]=='[')
        {
            c = strchr(argv[i], ']');
            if (!c)
                continue;
            port = atoi(c+2);
            if (port<1||port>65535)
                continue;
            *c = '\0';

            bp = buffer_new(sizeof(struct sockaddr_in6));
            bp->len = sizeof(struct sockaddr_in6);
            memset(bp->buf, 0, sizeof(struct sockaddr_in6));
            ((struct sockaddr_in6 *)bp->buf)->sin6_family = AF_INET6;

            ret = inet_pton(AF_INET6, argv[i]+1, &((struct sockaddr_in6 *)bp->buf)->sin6_addr);
            if (!ret)
            {
                buffer_free(bp);
                continue;
            }
            ((struct sockaddr_in6 *)bp->buf)->sin6_port = htons(port);
            deque_append(addrlist, bp);
        }
        else
        {
            c = strchr(argv[i], ':');
            if (!c)
                continue;
            port = atoi(c+1);
            if (port<1||port>65535)
                continue;
            *c = '\0';

            bp = buffer_new(sizeof(struct sockaddr_in));
            bp->len = sizeof(struct sockaddr_in);
            memset(bp->buf, 0, sizeof(struct sockaddr_in));
            ((struct sockaddr_in *)bp->buf)->sin_family = AF_INET;

            ret = inet_pton(AF_INET, argv[i], &((struct sockaddr_in *)bp->buf)->sin_addr);
            if (!ret)
            {
                buffer_free(bp);
                continue;
            }
            ((struct sockaddr_in *)bp->buf)->sin_port = htons(port);
            deque_append(addrlist, bp);
        }

    }

    SSL_load_error_strings();
    SSL_library_init();
    BIO_s_custom_meth_init();

    const SSL_METHOD *mtd = DTLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(mtd);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_use_certificate_chain_file(ctx, "server-cert.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    fprintf(stderr, "SSL_CTX_load_verify_locations -> %d\n", ret);
    ret = SSL_CTX_set_default_verify_file(ctx);
    fprintf(stderr, "SSL_CTX_set_default_verify_file -> %d\n", ret);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int run = 0;
    struct epoll_event epe = {0};

    DEQUE_FOREACH(i, addrlist)
    {
        buffer_t *bp = (buffer_t *)i->p;
        assert(bp->len > 4);

        epe.data.fd = socket(((struct sockaddr *)bp->buf)->sa_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

        fprintf(stderr, "new socket fd: %d\n", epe.data.fd);
        dump_addr((struct sockaddr *)bp->buf, "try bind: ");
        bind_error = bind(epe.data.fd, (struct sockaddr *)bp->buf, (socklen_t)bp->len);
        assert(!bind_error);

        epe.events = EPOLLIN|EPOLLET;
        epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

        run = 1;
    }

    signal(SIGINT, signal_handler);

    hashtable_t *ht = ht256_new();

    server_session_t *session = server_session_new(ctx);

    buffer_t *packet;
    packet = buffer_new(2000);

    int new_line = 1;

    while (run)
    {
        ret = epoll_wait(epfd, &epe, 1, TIME_OUT);

        if (ret==-1)
            break;
        else if (ret==0)
        {
            time_t curtime;
            time(&curtime);
            char *tmp = ctime(&curtime);
            tmp[strlen(tmp)-1] = '\0';
            fprintf(stderr, "wall time: %s\r", tmp);
            new_line = 1;
            continue;
        }

        if (new_line)
        {
            fputc('\n', stderr);
            new_line = 0;
        }

        while (1)
        {
            buffer_t *peer_addr_buf;
            socklen_t peer_addr_len;

            peer_addr_len = (socklen_t) session->data.txaddr_buf.cap;
            packet->len = recvfrom(epe.data.fd, packet->buf, packet->cap, 0, &(session->data.txaddr), &peer_addr_len);
            if (packet->len < 0)
            {
                break;
            }
            peer_addr_buf = &(session->data.txaddr_buf);
            peer_addr_buf->len = (int) peer_addr_len;
            server_session_t *existing_sess = (server_session_t *) ht_search(ht, peer_addr_buf);
            if (!existing_sess)
            {
                session->data.txfd = epe.data.fd;
                server_append_incoming_packet(session, packet);
                packet = buffer_new(2000);
                ret = DTLSv1_listen(session->ssl, NULL);
                // Note:
                // DTLSv1_listen() returns 1 only if the client has sent us a "Client Hello" packet with a valid cookie.
                // If there is no valid cookie in the "Client Hello" packet, DTLSv1_listen() will return 0 instead of 1.
                if (ret==1)
                {
                    ht_insert(ht, peer_addr_buf, session);
                    server_try_accepting_handshake(session);
                    session = server_session_new(ctx);
                }
                continue;
            }

            server_append_incoming_packet(existing_sess, packet);
            packet = buffer_new(2000);

            if (!server_hanshake_is_done(existing_sess))
            {
                server_try_accepting_handshake(existing_sess);
                continue;
            }

            // Read and write DTLS application data:
            char buf[2000];
            int n;
            if ((n = server_decrypt_incomming_packet(existing_sess, buf, sizeof(buf))) <= 0)
            {
                fprintf(stderr, "Info: No more application data packet from peer IP:port = %s\n", sdump_addr(&(existing_sess->data.txaddr)));
                int stateflag = SSL_get_shutdown(existing_sess->ssl);
                if (stateflag & SSL_RECEIVED_SHUTDOWN)
                {
                    int shutdown_status;
                    shutdown_status = SSL_shutdown(existing_sess->ssl);
                    if (1 == shutdown_status)
                    {
                        fprintf(stderr, "DEBUG: SSL_shutdown() success.\n");
                    }
                    else
                    {
                        fprintf(stderr, "DEBUG: LINE=%d\n", __LINE__);
                        fprintf(stderr, "WARNING: SSL_shutdown() returns 0x%X\n", shutdown_status);
                    }
                    ht_delete(ht, peer_addr_buf);
                    fprintf(stderr, "Info: peer %s has been removed from hash table\n", sdump_addr(&(existing_sess->data.txaddr)));
                    server_session_free(&existing_sess);
                }
                continue;
            }
            if ((n==6 && strncmp(buf, "whoami", 6)==0) || (n==7 && strncmp(buf, "whoami\n", 7)==0))
            {
                const char *tmp = sdump_addr(&existing_sess->data.txaddr);
                server_encrypt_and_send(existing_sess, tmp, strlen(tmp));
                server_encrypt_and_send(existing_sess, "\n", 1); // "\n" for openssl s_client
                continue;
            }

            if ((n==4 && strncmp(buf, "ping", 4)==0) || (n==5 && strncmp(buf, "ping\n", 5)==0))
            {
                server_encrypt_and_send(existing_sess, "pong\n", 5);
                continue;
            }

            if ((n>=5 && strncmp(buf, "echo ", 5)==0))
            {
                server_encrypt_and_send(existing_sess, buf+5, n-5);
                continue;
            }

            if ((n==5 && strncmp(buf, "echo\n", 5)==0))
            {
                server_encrypt_and_send(existing_sess, "\n", 1); // handle "echo\n" without parameters
                continue;
            }

            if ((n==5 && strncmp(buf, "stats", 5)==0) || (n==6 && strncmp(buf, "stats\n", 6)==0))
            {
                char replymsg[1400];
                int cnt; // bytes counter
                int delta;
                cnt = 0;
                delta = snprintf(replymsg, sizeof(replymsg), "users:\n");
                cnt += delta;
                HT_FOREACH(i, ht)
                {
                    delta = snprintf(replymsg+cnt, sizeof(replymsg)-cnt, "%s;\n", sdump_addr(&((server_session_t *)i->value)->data.txaddr));
                    if (cnt+delta >= sizeof(replymsg)-1)
                    {
                        server_encrypt_and_send(existing_sess, replymsg, cnt);
                        cnt = 0;
                        delta = snprintf(replymsg, sizeof(replymsg), "%s;\n", sdump_addr(&((server_session_t *)i->value)->data.txaddr));
                    }
                    cnt += delta;
                }
                server_encrypt_and_send(existing_sess, replymsg, cnt);
                continue;
            }

            if (n>3 && strncmp(buf, "bc ", 3)==0)
            {
                HT_FOREACH(i, ht)
                {
                    server_encrypt_and_send((server_session_t *)i->value, buf+3, n-3);
                }
                continue;
            }

            if (n>=2 && strncmp(buf, "bc", 2)==0)
            {
                const char CmdHint[] = "Usage: bc <some text>\n";
                const int CmdHintLen = sizeof(CmdHint)-1;
                server_encrypt_and_send(existing_sess, CmdHint, CmdHintLen);
                continue;
            }

            /* Got an unrecognized command, send hint message to client */
            {
                const char UnknownCmdHint[] = "Sorry, I don't understand...\n";
                int UnknownCmdHintLen = sizeof(UnknownCmdHint) - 1;

                server_encrypt_and_send(existing_sess, UnknownCmdHint, UnknownCmdHintLen);
                server_encrypt_and_send(existing_sess, SERVER_HINTS, SERVER_HINTS_LEN);
            }
        }
    }

    buffer_free(packet);

    server_session_free(&session);

    server_session_t *sess = NULL;
    HT_FOREACH(i, ht)
    {
        sess = (server_session_t *)i->value;
        SSL_shutdown(sess->ssl);
        dump_addr(&(sess->data.txaddr), "|| ");
        server_session_free(&sess);
    }
    ht_free(ht);
    SSL_CTX_free(ctx);

    DEQUE_FOREACH(i, addrlist)
        buffer_free((buffer_t *)i->p);

    deque_free(addrlist);

    BIO_s_custom_meth_deinit();
    return 0;
}

typedef union access_u
{
    uint_fast64_t u64;
    uint32_t u32[2];
    uint16_t u16[4];
    uint8_t u8[8];
} access_t;

static int ht256_hash(buffer_t *bp)
{
    access_t sum = {0};
    uintptr_t p = (uintptr_t)bp->buf;
    int n = bp->len;

    if (p&0x01 && n>=1)
    {
        *sum.u8 ^= *(uint8_t *)p++;
        n -= 1;
    }
    if (p&0x02 && n>=2)
    {
        *sum.u16 ^= *(uint16_t *)p++;
        n -= 2;
    }
    if (p&0x04 && n>=4)
    {
        *sum.u32 ^= *(uint32_t *)p++;
        n -= 4;
    }
    while (n>=8)
    {
        sum.u64 ^= *(uint64_t *)p++;
        n -= 8;
    }
    sum.u32[0] ^= sum.u32[1];
    sum.u32[1] = 0;
    if (n>=4)
    {
        *sum.u32 ^= *(uint32_t *)p++;
        n -= 4;
    }
    sum.u16[0] ^= sum.u16[1];
    sum.u16[1] = 0;
    if (n>=2)
    {
        *sum.u16 ^= *(uint16_t *)p++;
        n -= 2;
    }
    sum.u8[0] ^= sum.u8[1];
    sum.u8[1] = 0;
    if (n>=1)
    {
        *sum.u8 ^= *(uint8_t *)p++;
        n -= 1;
    }


    return sum.u8[0];
}

hashtable_t *ht256_new(void)
{
    hashtable_t *htp = (hashtable_t  *)malloc(sizeof(hashtable_t)+256*sizeof(deque_t));
    htp->hash = ht256_hash;
    htp->nbucket = 256;

    for (int i=0; i<256; ++i)
    {
        deque_init(htp->bucket+i);
    }
    return htp;
}

void ht_reset(hashtable_t *htp)
{
    assert(htp);

    for (int i=0; i<htp->nbucket; ++i)
    {
        deque_t *dp = &htp->bucket[i];
        while (dp->head)
        {
            ht_node_t *hnp = (ht_node_t *)deque_popleft(dp);
            free(hnp);
        }
    }
}

void ht_free(hashtable_t *htp)
{
    assert(htp);
    ht_reset(htp);
    free(htp);
}

void *ht_search(hashtable_t *htp, buffer_t *key)
{
    assert(htp);
    assert(key);

    DEQUE_FOREACH(i, htp->bucket+htp->hash(key))
    {
        if (buffer_eq(key, ((ht_node_t *)i->p)->key))
        {
            return ((ht_node_t *)i->p)->value;
        }
    }

    return NULL;
}

void *ht_insert(hashtable_t *htp, buffer_t *key, void *value)
{
    assert(htp);
    assert(key);

    ht_node_t *node = (ht_node_t *)malloc(sizeof(ht_node_t));
    node->key = key;
    node->value = value;

    deque_appendleft(&htp->bucket[htp->hash(key)], (void *)node);
}

int ht_delete(hashtable_t *htp, buffer_t *key)
{
    assert(htp);
    assert(key);

    deque_t *dp = htp->bucket+htp->hash(key);
    DEQUE_FOREACH(i, dp)
    {
        if (buffer_eq(key, ((ht_node_t *)i->p)->key))
        {
            free((ht_node_t *)i->p);
            deque_remove(dp, i);
            return 1;
        }
    }

    return 0;
}
