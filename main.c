#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <openssl/ssl.h>

#include "util.h"
#include "server.h"


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


void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "Interrupt from keyboard\n");
    else
        fprintf(stderr, "unknown signal[%d]\n", sig);
    fflush(stderr);
}

enum
{
    TIME_OUT = 8000 // ms
};

char ServerAppHints[] =
    "My server supports the following commands:\n"
    "  1. ping returns pong\n"
    "  2. echo <some text> returns <some text>\n"
    "  3. whoami returns client's address and port seen by server\n"
    "  4. stats returns a list of server currently serving clients\n"
    "  5. bc <some text> broadcast <some text> to all clients\n"
    "You may try these commands youself and see how they work.\n"
    "Good luck!\n";
const int ServerAppHintsLen = sizeof(ServerAppHints) - 1;


static int app_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
static int app_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);

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

    SSL_CTX_set_cookie_generate_cb(ctx, app_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, app_verify_cookie);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int run = 0;
    struct epoll_event epe = {0};

    DEQUE_FOREACH(i, addrlist)
    {
        buffer_t *bp = (buffer_t *)i->p;
        assert(bp->len > 4);

        epe.data.fd = socket(((struct sockaddr *)bp->buf)->sa_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

        /* DTLS requires the IP don't fragment (DF) bit to be set */
        #if defined(__linux__) && defined(IP_MTU_DISCOVER)
        {
            int optval = IP_PMTUDISC_DO;
            setsockopt(epe.data.fd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *) &optval, sizeof(optval));
            /* 备注:
            Linux 内核提供了一个禁用IPv4 PMTU Discover特性的开关
            当/proc目录下的文件 /proc/sys/net/ipv4/ip_no_pmtu_disc 的字符串为"0"时,
            表示内核允许探测PMTU实际长度
            */
        }
        #endif
        #if defined(__FreeBSD__) && defined(IP_DONTFRAG)
        {
            int optval = 1;
            setsockopt(epe.data.fd, IPPROTO_IP, IP_DONTFRAG, (const void *) &optval, sizeof(optval));
        }
        #endif

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
            socklen_t peer_addr_len;

            peer_addr_len = (socklen_t) session->data.txaddr_buf.cap;
            packet->len = recvfrom(epe.data.fd, packet->buf, packet->cap, 0, &(session->data.txaddr), &peer_addr_len);
            if (packet->len < 0)
            {
                break;
            }
            session->data.txaddr_buf.len = peer_addr_len;

            if (packet->len < SDP_ID_MAX_BYTES)
            {
                break;
            }
            memcpy(session->data.sdp_id, packet->buf, SDP_ID_MAX_BYTES);
            buffer_t *id = &(session->data.head);
            id->len = id->cap = SDP_ID_MAX_BYTES;
            server_session_t *existing_sess = (server_session_t *) ht_search(ht, id);
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
                    ht_insert(ht, id, session);
                    server_try_accepting_handshake(session);
                    if (server_hanshake_is_done(session))
                    {
                        server_encrypt_and_send(session, ServerAppHints, ServerAppHintsLen);
                    }
                    session = server_session_new(ctx);
                }
                continue;
            }

            server_append_incoming_packet(existing_sess, packet);
            packet = buffer_new(2000);

            if (!server_hanshake_is_done(existing_sess))
            {
                server_try_accepting_handshake(existing_sess);
                if (server_hanshake_is_done(existing_sess))
                {
                    server_encrypt_and_send(existing_sess, ServerAppHints, ServerAppHintsLen);
                }
                continue;
            }

            // Read and write DTLS application data:
            char buf[2000];
            int n;
            if ((n = server_decrypt_incoming_packet(existing_sess, buf, sizeof(buf))) <= 0)
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
                    ht_delete(ht, id);
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
                server_encrypt_and_send(existing_sess, ServerAppHints, ServerAppHintsLen);
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


#include <openssl/evp.h>
#include <openssl/rand.h>

#define APP_COOKIE_SECRET_KEY_LENGTH 16
char app_cookie_secret_key[APP_COOKIE_SECRET_KEY_LENGTH]={0};
int app_is_cookie_secret_key_initialized = 0;

#define APP_FEATURE_ENABLE_SM3 1
#if defined(APP_FEATURE_ENABLE_SM3) && defined(OPENSSL_NO_SM3)
#error "APP_FEATURE_ENABLE_SM3"// You must build customized OpenSSL with SM3 feture enabled!
#endif

#if defined(APP_FEATURE_ENABLE_SM3) && !defined(OPENSSL_NO_SM3)
#define app_selected_hash_algorithm EVP_sm3()
#else
#define app_selected_hash_algorithm EVP_sha256()
#endif

int app_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    BIO *bio = NULL;
    custom_bio_data_t *cbiodata = NULL;
    const unsigned char *src = NULL;
    int n = 0;
    unsigned char hmac_result[DTLS1_COOKIE_LENGTH] = {0}; // DTLS1_COOKIE_LENGTH = 256 但 DTLS v1.2 协议 (RFC 6347) 规定 cookie 长度的最大值为 255 字节(即2^8 -1)
    unsigned int result_len = sizeof(hmac_result);

    if (!app_is_cookie_secret_key_initialized)
    {
        if (!RAND_bytes(app_cookie_secret_key, APP_COOKIE_SECRET_KEY_LENGTH))
        {
            fprintf(stderr, "ERROR! Can not set random cookie secret key!\n");
            return 0;
        }
	    app_is_cookie_secret_key_initialized = 1;
	}

    bio = SSL_get_wbio(ssl);
    cbiodata = BIO_get_data(bio);
    src = cbiodata->txaddr_buf.buf;
    n = cbiodata->txaddr_buf.len;
    result_len = sizeof(hmac_result);
    HMAC(app_selected_hash_algorithm, app_cookie_secret_key, APP_COOKIE_SECRET_KEY_LENGTH, src, n, hmac_result, &result_len);
    assert(result_len <= 255);
    if (result_len > 255)
    {
        result_len = 255;
    }
    memcpy(cookie, hmac_result, (size_t)result_len);
    *cookie_len = result_len;
    return 1;
}

int app_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    int is_valid = 0;
    BIO *bio = NULL;
    custom_bio_data_t *cbiodata = NULL;
    const unsigned char *src = NULL;
    int n = 0;
    HMAC_CTX *hmac_calc = NULL;
    unsigned char hmac_result[DTLS1_COOKIE_LENGTH] = {0}; // DTLS1_COOKIE_LENGTH = 256
    unsigned int result_len = sizeof(hmac_result);

    hmac_calc = HMAC_CTX_new();
    HMAC_Init_ex(hmac_calc, app_cookie_secret_key, APP_COOKIE_SECRET_KEY_LENGTH, app_selected_hash_algorithm, NULL);
    if (HMAC_size(hmac_calc) != cookie_len)
    {
        is_valid = 0;
        goto VERIFY_COOKIE_CLEANUP;
    }

    bio = SSL_get_wbio(ssl);
    cbiodata = BIO_get_data(bio);
    src = cbiodata->txaddr_buf.buf;
    n = cbiodata->txaddr_buf.len;
    HMAC_Update(hmac_calc, src, n);
    result_len = sizeof(hmac_result);
    HMAC_Final(hmac_calc, hmac_result, &result_len);
    is_valid = (memcmp(cookie, hmac_result, HMAC_size(hmac_calc)) == 0);

VERIFY_COOKIE_CLEANUP:
    HMAC_CTX_free(hmac_calc);
    return is_valid;
}
