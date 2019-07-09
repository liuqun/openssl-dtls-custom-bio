#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>

#include "util.h"
#include "cbio.h"

// #define fprintf(...)

int BIO_s_custom_write_ex(BIO *b, const char *data, size_t dlen, size_t *written)
{
    (void) b;
    (void) data;
    (void) dlen;
    (void) written;
    fprintf(stderr, "BIO_s_custom_write_ex(BIO[0x%p], data[0x%p], dlen[%ld], *written[%ld])\n", (void*)b, (const void*)data, dlen, *written);
    fflush(stderr);

    return -1;
}

int BIO_s_custom_write(BIO *b, const char *data, int dlen)
{
    (void) b;
    int ret;
    custom_bio_data_t *cdp;

    ret = -1;
    fprintf(stderr, "BIO_s_custom_write(BIO[0x%p], buf[0x%p], dlen[%d])\n", (void *)b, (const void *)data, dlen);
    fflush(stderr);
    cdp = (custom_bio_data_t *)BIO_get_data(b);

    dump_addr((struct sockaddr *)&cdp->txaddr, ">> ");
//     dump_hex((unsigned const char *)data, dlen, "    ");
    char totalbuf[2000]={0}; // const size_t Max = sizeof(totalbuf);
    memcpy(totalbuf, cdp->sdp_id, SDP_ID_MAX_BYTES);
    memcpy(totalbuf + SDP_ID_MAX_BYTES, data, (size_t)dlen);
    int totallen = dlen + SDP_ID_MAX_BYTES;
    ret = (int) sendto(cdp->txfd, totalbuf, (size_t)totallen, 0, (struct sockaddr *)&cdp->txaddr, (socklen_t)cdp->txaddr_buf.len);
    if (ret >= 0)
        fprintf(stderr, "  %d bytes sent\n", ret);
    else
        fprintf(stderr, "  ret: %d errno: [%d] %s\n", ret, errno, strerror(errno));

    return ret;
}

int BIO_s_custom_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes)
{
    (void) b;
    (void) data;
    (void) dlen;
    (void) readbytes;
    fprintf(stderr, "BIO_s_custom_read_ex(BIO[0x%p], data[0x%p], dlen[%ld], *readbytes[%ld])\n", (void *)b, (const void *)data, dlen, *readbytes);
    fflush(stderr);

    return -1;
}

int BIO_s_custom_read(BIO *b, char *data, int dlen)
{
    (void) b;
    int len = -1;
    custom_bio_data_t *cdp;
    deque_t *dp;
    buffer_t *bp;

    fprintf(stderr, "BIO_s_custom_read(BIO[0x%p], data[0x%p], dlen[%d])\n", (void *)b, (const void *)data, dlen);
    fprintf(stderr, "  probe peekmode %d\n",
            ((custom_bio_data_t *)BIO_get_data(b))->peekmode);
    fflush(stderr);

    cdp = (custom_bio_data_t *)BIO_get_data(b);
    dp = &cdp->rxqueue;
    fprintf(stderr, "  data[0x%p] queue: %d\n", (void *)dp, (int)deque_count(dp));
    if (!dp->head)
    {
        return -1;
    }
    else
    {
        if (((custom_bio_data_t *)BIO_get_data(b))->peekmode)
            bp = (buffer_t *)deque_peekleft(dp);
        else
            bp = (buffer_t *)deque_popleft(dp);
        fprintf(stderr, "  buf[0x%p]\n", (void *)bp);
        fflush(stderr);

        len = (bp->len<=dlen) ? bp->len : dlen;
        /* 去掉 SDP 层报头占用的 16 字节, 得到 DTLS 层实际长度 len */
        len -= SDP_ID_MAX_BYTES;
        memcpy(data, bp->buf+SDP_ID_MAX_BYTES, (size_t)len);

        if (!((custom_bio_data_t *)BIO_get_data(b))->peekmode)
            buffer_free(bp);
    }

    return len;
}

int BIO_s_custom_gets(BIO *b, char *data, int size);

int BIO_s_custom_puts(BIO *b, const char *data);

#if defined(OPENSSL_NO_SCTP)
/* I would like the following definitions to be available even when SCTP feature was disabled in OpenSSL */
#define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY 51
#define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY 52
#define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD 53
#define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO 60
#define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO 61
#define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO 62
#define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO 63
#define BIO_CTRL_DGRAM_SCTP_GET_PRINFO 64
#define BIO_CTRL_DGRAM_SCTP_SET_PRINFO 65
#define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN 70
#endif /* end SCTP stuff */

long BIO_s_custom_ctrl(BIO *b, int cmd, long larg, void *pargs)
{
    (void) b;
    (void) pargs;
    long ret = 0;

//     fprintf(stderr, "BIO_s_custom_ctrl(BIO[0x%016lX], cmd[%d], larg[%ld], pargs[0x%016lX])\n", b, cmd, larg, pargs);
    fflush(stderr);

    switch(cmd)
    {
        case BIO_CTRL_FLUSH: // 11
        case BIO_CTRL_DGRAM_SET_CONNECTED: // 32
        case BIO_CTRL_DGRAM_SET_PEER: // 44
        case BIO_CTRL_DGRAM_GET_PEER: // 46
            ret = 1;
            break;
        case BIO_CTRL_WPENDING: // 13
            ret = 0;
            break;
        case BIO_CTRL_DGRAM_QUERY_MTU: // 40
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU: // 47
            ret = 1400;
//             ret = 9000; // jumbo?
            break;
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD: // 49
            ret = 96; // random guess
            break;
        case BIO_CTRL_DGRAM_SET_PEEK_MODE: // 71
            ((custom_bio_data_t *)BIO_get_data(b))->peekmode = !!larg;
            ret = 1;
            break;
        case BIO_CTRL_PUSH: // 6
        case BIO_CTRL_POP: // 7
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: // 45
            ret = 0;
            break;
        /* We need to handle/ignore the following SCTP control commands: */
        case BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY:
        case BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY:
        case BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD:
        case BIO_CTRL_DGRAM_SCTP_GET_SNDINFO:
        case BIO_CTRL_DGRAM_SCTP_SET_SNDINFO:
        case BIO_CTRL_DGRAM_SCTP_GET_RCVINFO:
        case BIO_CTRL_DGRAM_SCTP_SET_RCVINFO:
        case BIO_CTRL_DGRAM_SCTP_GET_PRINFO:
        case BIO_CTRL_DGRAM_SCTP_SET_PRINFO:
        case BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN:
            /* Tested against OpenSSL 1.1.1 shipped by RedHat RHEL-8.0.
             * See bug report: https://github.com/stepheny/openssl-dtls-custom-bio/issues/3
             */
            ret = 0;
            break;
        default:
            fprintf(stderr, "BIO_s_custom_ctrl(BIO[0x%p], cmd[%d], larg[%ld], pargs[0x%p])\n", (void *)b, cmd, larg, pargs);
            fprintf(stderr, "  unknown cmd: %d\n", cmd);
            fflush(stderr);
            ret = 0;
            raise(SIGTRAP);
            break;
    }

    return ret;
}

int BIO_s_custom_create(BIO *b)
{
    (void) b;
    fprintf(stderr, "BIO_s_custom_create(BIO[0x%p])\n", (void *)b);
    fflush(stderr);

    return 1;
}

int BIO_s_custom_destroy(BIO *b)
{
    (void) b;
    fprintf(stderr, "BIO_s_custom_destroy(BIO[0x%p])\n", (void *)b);
    fflush(stderr);

    return 1;
}

// long BIO_s_custom_callback_ctrl(BIO *, int, BIO_info_cb *);

static BIO_METHOD *_BIO_s_custom = NULL;
BIO_METHOD *BIO_s_custom(void)
{
    if (_BIO_s_custom)
    {
        return _BIO_s_custom;
    }
    BIO_s_custom_meth_init();
    return _BIO_s_custom;
}

void BIO_s_custom_meth_init(void)
{
    if (_BIO_s_custom)
    {
        return;
    }

    _BIO_s_custom = BIO_meth_new(BIO_get_new_index()|BIO_TYPE_SOURCE_SINK, "BIO_s_custom");

    BIO_meth_set_write(_BIO_s_custom, BIO_s_custom_write);
    BIO_meth_set_read(_BIO_s_custom, BIO_s_custom_read);
    BIO_meth_set_ctrl(_BIO_s_custom, BIO_s_custom_ctrl);
    BIO_meth_set_create(_BIO_s_custom, BIO_s_custom_create);
    BIO_meth_set_destroy(_BIO_s_custom, BIO_s_custom_destroy);
}

void BIO_s_custom_meth_deinit(void)
{
    if (_BIO_s_custom)
    {
        BIO_meth_free(_BIO_s_custom);
    }
    _BIO_s_custom = NULL;
}

#undef fprintf
