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

typedef struct my_server_udp_channel_t server_udp_channel_t;

typedef void (*custom_callback_fn_t)(server_udp_channel_t *channel, void *extra_arg);

struct my_server_udp_channel_t
{
    custom_bio_data_t data;
    SSL *ssl;

    int is_handshake_accepted;
    struct {
        custom_callback_fn_t on_handshake_accepted_cb;
        void *on_handshake_accepted_extra_arg;
    };
};

int server_hanshake_is_done(server_udp_channel_t *channel)
{
    return channel->is_handshake_accepted;
}

void server_send_greetings_to_client(server_udp_channel_t *channel, void *extra_greeting_arg)
{
    const char *DefaultGreetingMsg = "(Server greeting message is empty by default...)\n";
    const char *msg = (const char *)extra_greeting_arg;
    size_t n=0;

    if (!msg || (n=strlen(msg)) <= 0)
    {
        n = strlen(DefaultGreetingMsg);
        msg = DefaultGreetingMsg;
    }
    SSL_write(channel->ssl, msg, n);
}

server_udp_channel_t * server_udp_channel_new_from_ctx(SSL_CTX *ctx)
{
    BIO *bio = NULL;
    struct my_server_udp_channel_t *channel = NULL;

    channel = (server_udp_channel_t *)calloc(1, sizeof(server_udp_channel_t));

    channel->data.txaddr_buf.cap = channel->data.txaddr_buf.len = sizeof(struct sockaddr_storage);
    memset(&channel->data.txaddr_storage, 0x00, sizeof(struct sockaddr_storage));
    deque_init(&(channel->data.rxqueue));
    channel->data.peekmode = 0;

    bio = BIO_new(BIO_s_custom());
    BIO_set_data(bio, (void *)&channel->data);
    BIO_set_init(bio, 1);
    channel->ssl = SSL_new(ctx);
    SSL_set_bio(channel->ssl, bio, bio);

    channel->is_handshake_accepted = 0;
    channel->on_handshake_accepted_cb = server_send_greetings_to_client;
    channel->on_handshake_accepted_extra_arg = SERVER_HINTS;

    return channel;
}

void server_udp_channel_free(server_udp_channel_t **pp)
{
    server_udp_channel_t *p = NULL;

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

void server_append_incoming_packet(server_udp_channel_t *chnl, buffer_t *packet)
{
    deque_append(&(chnl->data.rxqueue), packet);
}

int server_get(server_udp_channel_t *chnl, void *out_buf, size_t out_buf_max_bytes)
{
    size_t decrypted=0;
    int max = (int) out_buf_max_bytes;
    int ret;

    if ((ret = SSL_read(chnl->ssl, out_buf, out_buf_max_bytes)) < 0)
    {
        int e = SSL_get_error(chnl->ssl, ret);
        if (SSL_ERROR_SSL == e)
        {
            fprintf(stderr, "SSL_ERROR_SSL!\n");
            ERR_print_errors_fp(stderr);
        }
        return 0;
    }
    return ret;
}

void server_try_doing_handshake(server_udp_channel_t *chnl)
{
    if (chnl->is_handshake_accepted)
    {
        return;
    }

    if (SSL_accept(chnl->ssl) != 1)
    {
        chnl->is_handshake_accepted = 0;
        return;
    }

    dump_addr(&chnl->data.txaddr, "user connected: ");
    chnl->is_handshake_accepted = 1;
    if (chnl->on_handshake_accepted_cb)
    {
        chnl->on_handshake_accepted_cb(chnl, chnl->on_handshake_accepted_extra_arg);
    }
    return;
}

void server_put(server_udp_channel_t *chnl, const void *datablock, size_t blocksize)
{
    SSL_write(chnl->ssl, datablock, (int)blocksize);
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

    server_udp_channel_t *channel = server_udp_channel_new_from_ctx(ctx);

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

            peer_addr_len = (socklen_t) channel->data.txaddr_buf.cap;
            packet->len = recvfrom(epe.data.fd, packet->buf, packet->cap, 0, &(channel->data.txaddr), &peer_addr_len);
            if (packet->len < 0)
            {
                break;
            }
            peer_addr_buf = &(channel->data.txaddr_buf);
            peer_addr_buf->len = (int) peer_addr_len;
            server_udp_channel_t *chnl = (server_udp_channel_t *) ht_search(ht, peer_addr_buf);
            if (!chnl)
            {
                channel->data.txfd = epe.data.fd;
                server_append_incoming_packet(channel, packet);
                packet = buffer_new(2000);
                ret = DTLSv1_listen(channel->ssl, NULL);
                if (ret==1) // if the client sents us a "Client Hello" packet with a valid cookie
                {
                    ht_insert(ht, peer_addr_buf, channel);
                    server_try_doing_handshake(channel);
                    if (!server_hanshake_is_done(channel))
                    {
                        int e;
                        e = SSL_get_error(channel->ssl, ret);
                        if (SSL_ERROR_SSL == e)
                        {
                            fprintf(stderr, "!!!! SSL_get_error -> %d\n", e);
                            ERR_print_errors_fp(stderr);
                            SSL_free(channel->ssl);
                            ht_delete(ht, peer_addr_buf);
                            free(channel);
                        }
                    }

                    channel = server_udp_channel_new_from_ctx(ctx);
                }
                continue;
            }

            server_append_incoming_packet(chnl, packet);
            packet = buffer_new(2000);

            int stateflag = SSL_get_shutdown(chnl->ssl);
            if (stateflag & SSL_RECEIVED_SHUTDOWN)
            {
                if (!(stateflag & SSL_SENT_SHUTDOWN))
                {
                    SSL_shutdown(chnl->ssl);
                }
                ht_delete(ht, peer_addr_buf);
                server_udp_channel_free(&chnl);
                continue;
            }

            if (!server_hanshake_is_done(chnl))
            {
                server_try_doing_handshake(chnl);
                if (!server_hanshake_is_done(chnl))
                {
                    int e;
                    e = SSL_get_error(chnl->ssl, ret);
                    if (SSL_ERROR_SSL == e)
                    {
                        fprintf(stderr, "!!!! SSL_get_error -> %d\n", e);
                        ERR_print_errors_fp(stderr);
                        ht_delete(ht, peer_addr_buf);
                        server_udp_channel_free(&chnl);
                        continue;
                    }
                }
                continue;
            }

            // Read and write DTLS application data:
            char buf[2000];
            int n;
            n = server_get(chnl, buf, sizeof(buf));
            if (n <= 0)
            {
                continue;
            }
            if ((n==6 && strncmp(buf, "whoami", 6)==0) || (n==7 && strncmp(buf, "whoami\n", 7)==0))
            {
                const char *tmp = sdump_addr(&chnl->data.txaddr);
                server_put(chnl, tmp, strlen(tmp));
                server_put(chnl, "\n", 1); // "\n" for openssl s_client
                continue;
            }

            if ((n==4 && strncmp(buf, "ping", 4)==0) || (n==5 && strncmp(buf, "ping\n", 5)==0))
            {
                server_put(chnl, "pong", 4);
                server_put(chnl, "\n", 1); // "\n" for openssl s_client
                continue;
            }

            if ((n>=5 && strncmp(buf, "echo ", 5)==0))
            {
                server_put(chnl, buf+5, n-5);
                continue;
            }

            if ((n==5 && strncmp(buf, "echo\n", 5)==0))
            {
                server_put(chnl, "\n", 1); // handle "echo\n" without parameters
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
                    delta = snprintf(replymsg+cnt, sizeof(replymsg)-cnt, "%s;\n", sdump_addr(&((server_udp_channel_t *)i->value)->data.txaddr));
                    if (cnt+delta >= sizeof(replymsg)-1)
                    {
                        server_put(chnl, replymsg, cnt);
                        cnt = 0;
                        delta = snprintf(replymsg, sizeof(replymsg), "%s;\n", sdump_addr(&((server_udp_channel_t *)i->value)->data.txaddr));
                    }
                    cnt += delta;
                }
                server_put(chnl, replymsg, cnt);
                continue;
            }

            if (n>3 && strncmp(buf, "bc ", 3)==0)
            {
                HT_FOREACH(i, ht)
                {
                    server_put((server_udp_channel_t *)i->value, buf+3, n-3);
                }
                continue;
            }

            if (n>=2 && strncmp(buf, "bc", 2)==0)
            {
                const char CmdHint[] = "Usage: bc <some text>\n";
                const int CmdHintLen = sizeof(CmdHint)-1;
                server_put(chnl, CmdHint, CmdHintLen);
                continue;
            }

            /* Got an unrecognized command, send hint message to client */
            {
                const char UnknownCmdHint[] = "Sorry, I don't understand...\n";
                int UnknownCmdHintLen = sizeof(UnknownCmdHint) - 1;

                server_put(chnl, UnknownCmdHint, UnknownCmdHintLen);
                server_put(chnl, SERVER_HINTS, SERVER_HINTS_LEN);
            }
        }
    }

    buffer_free(packet);

    server_udp_channel_free(&channel);

    server_udp_channel_t *chnl = NULL;
    HT_FOREACH(i, ht)
    {
        chnl = (server_udp_channel_t *)i->value;
        SSL_shutdown(chnl->ssl);
        dump_addr(&(chnl->data.txaddr), "|| ");
        server_udp_channel_free(&chnl);
    }
    ht_free(ht);
    SSL_CTX_free(ctx);

    DEQUE_FOREACH(i, addrlist)
        buffer_free((buffer_t *)i->p);

    deque_free(addrlist);

    BIO_s_custom_meth_deinit();
    return 0;
}
