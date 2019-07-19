#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <readline/readline.h>

#include "util.h"
#include "cbio.h"

enum
{
    TIME_OUT = 8000 // ms
};

void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "Interrupt from keyboard\n");
    else
        fprintf(stderr, "unknown signal[%d]\n", sig);
    fflush(stderr);
}

SSL *ssl;

int run = 1;
int connected = 0;

void readline_handler(char *line)
{
    if (line)
    {
        if (connected)
            SSL_write(ssl, line, strlen(line));
        else
            fputs("not connected\n", stderr);
        free(line);
    }
    else
    {
        fprintf(stderr, "^D\n");
        run = 0;
        if (connected)
            SSL_shutdown(ssl);
    }
}

int main(int argc, char **argv)
{
    int ret;

    if (argc!=2)
    {
        fputs("usage:\n"
        "  client 127.0.0.1:1234\n"
        "  client [::1]:1234\n", stderr);

        exit(0);
    }

    custom_bio_data_t cbio_data;
    xsock_t *xsock = &(cbio_data.xsock);
    char *c;
    int port;

    if (argv[1][0]=='[')
    {
        c = strchr(argv[1], ']');
        if (!c)
        {
            fputs("invalid target: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        port = atoi(c+2);
        if (port<1||port>65535)
        {
            fputs("invalid port: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        *c = '\0';

        cbio_data.txaddr.sa_family = AF_INET6;

        ret = inet_pton(AF_INET6, argv[1]+1, &cbio_data.txaddr_v6.sin6_addr);
        if (!ret)
        {
            fputs("invalid ipv6 address: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        cbio_data.txaddr_v6.sin6_port = htons(port);
        cbio_data.txaddr_buf.cap = sizeof(struct sockaddr_storage);
        cbio_data.txaddr_buf.len = sizeof(struct sockaddr_in6);
    }
    else
    {
        c = strchr(argv[1], ':');
        if (!c)
        {
            fputs("invalid target: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        port = atoi(c+1);
        if (port<1||port>65535)
        {
            fputs("invalid port: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        *c = '\0';

        cbio_data.txaddr.sa_family = AF_INET;

        ret = inet_pton(AF_INET, argv[1], &cbio_data.txaddr_v4.sin_addr);
        if (!ret)
        {
            fputs("invalid ipv4 address: ", stderr);
            fputs(argv[1], stderr);
            fputc('\n', stderr);

            exit(1);
        }
        cbio_data.txaddr_v4.sin_port = htons(port);
        cbio_data.txaddr_buf.cap = sizeof(struct sockaddr_storage);
        cbio_data.txaddr_buf.len = sizeof(struct sockaddr_in);
    }

    int sockfd = socket(cbio_data.txaddr.sa_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

    if (connect(sockfd, &cbio_data.txaddr, cbio_data.txaddr_buf.len))
    {
        fputs("failed to connect\n", stderr);

        exit(1);
    }
    cbio_data.txfd = sockfd;

    assert(sockfd);
    deque_init(&cbio_data.rxqueue);
    cbio_data.peekmode = 0;
    if (1) // FIXME: 正式版本必须改成由 SDP Controller 统一下发 SDP 会话 ID. 下列代码中填写的是随机数, 临时代表假的 SDP 会话 ID
    {
        char src_host_id[20]={0};// 20==XFS_HOST_ID_SIZE
        char dst_host_id[20]={0};

        RAND_bytes(src_host_id, sizeof(src_host_id));
        src_host_id[0] = '{';
        src_host_id[1] = '{';
        src_host_id[18] = '}';
        src_host_id[19] = '}';
        memset(dst_host_id, 0xFF, sizeof(dst_host_id));//FIXME: 此处无法确定目标主机ID, 简单的填写20字节全0xFF

        xsock_set_src_host_id(xsock, src_host_id);
        xsock_set_dst_host_id(xsock, dst_host_id);
        cbio_data.head.cap = XFS_XUDP_LAYER_HEADER_LENGTH;
        cbio_data.head.len = cbio_data.head.cap;
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event epe = {0};

    epe.data.fd = fileno(stdin);
    epe.events = EPOLLIN;

    epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);

    SSL_load_error_strings();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_use_certificate_chain_file(ctx, "client-cert.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM);
    ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    fprintf(stderr, "SSL_CTX_load_verify_locations -> %d\n", ret);
    ret = SSL_CTX_set_default_verify_file(ctx);
    fprintf(stderr, "SSL_CTX_set_default_verify_file -> %d\n", ret);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    ssl = SSL_new(ctx);

    BIO_s_custom_meth_init();
    BIO *custom_bio = BIO_new(BIO_s_custom());
    BIO_set_data(custom_bio, (void *)&cbio_data);
    BIO_set_init(custom_bio, 1);
    SSL_set_bio(ssl, custom_bio, custom_bio);

    epe.data.fd = sockfd;
    epe.events = EPOLLIN|EPOLLET;

    epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

    signal(SIGINT, signal_handler);

    buffer_t *packet;
    packet = buffer_new(2000);

    ret = SSL_connect(ssl);
    if (ret==1)
    {
        connected = 1;
        fputs("connected\n", stderr);
    }
    else if (SSL_get_error(ssl, ret)==SSL_ERROR_SSL)
    {
        dump_addr(&cbio_data.txaddr, "ssl error: ");
        ERR_print_errors_fp(stderr);
    }

    rl_callback_handler_install(">> ", readline_handler);

    while(run)
    {
        ret = epoll_wait(epfd, &epe, 1, TIME_OUT);
        if (ret<0)
        {
            if (connected)
                SSL_shutdown(ssl);

            break;
        }
        else if (ret==0) // time out
            continue;

        if (epe.data.fd==fileno(stdin))
            rl_callback_read_char();
        if (epe.data.fd==sockfd)
        {
            while ((packet->len=xsock_recv(xsock, epe.data.fd, packet->buf, packet->cap, 0))>=0)
            {
                fprintf(stderr, "\033[2K\r<< %d bytes\n", packet->len);

                deque_append(&cbio_data.rxqueue, packet);

                packet = buffer_new(2000);

                if (connected)
                {
                    packet->len = SSL_read(ssl, packet->buf, packet->cap);

                    if (packet->len>0)
                    {
                    packet->buf[packet->len] = '\0';
                    printf("RECV: %s\n", packet->buf);
                    }
                    else if (packet->len==0)
                    {
                        SSL_shutdown(ssl);
                        run = 0;
                    }
                }
                else
                {
                    ret = SSL_connect(ssl);

                    if (ret==1)
                    {
                        connected = 1;
                        fputs("connected\n", stderr);
                    }
                    else if (SSL_get_error(ssl, ret)==SSL_ERROR_SSL)
                    {
                        dump_addr(&cbio_data.txaddr, "ssl error: ");
                        ERR_print_errors_fp(stderr);

                        run = 0;
                        break;
                    }
                }
                rl_forced_update_display();
            }
        }
    }
    buffer_free(packet);

    deque_deinit(&cbio_data.rxqueue);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    BIO_s_custom_meth_deinit();

    rl_cleanup_after_signal();
    fputc('\n', stderr);

    close(sockfd);

    rl_callback_handler_remove();

    return 0;
}
