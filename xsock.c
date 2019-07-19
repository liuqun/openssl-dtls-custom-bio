#include <string.h> // memcpy()
#include <sys/socket.h> // sockaddr

#include "xsock.h"

/* 函数 xsock_recvfrom(): 按照新范式报文格式定义, 检查40字节主机ID编码 */
ssize_t xsock_recvfrom(xsock_t *thiz, int sockfd, unsigned char data[], size_t maxdatalen,
        int sockflags, struct sockaddr *remote_addr, socklen_t *addrlen)
{
    char incoming_bytes[3000]; //此处写死最大允许收包的字节数
    const size_t MAX_BYTES = sizeof(incoming_bytes);
    ssize_t total_received;

    memset(incoming_bytes, 0x55, MAX_BYTES);
    total_received = recvfrom(sockfd, incoming_bytes, MAX_BYTES, sockflags,
            remote_addr, addrlen);
    if (total_received < 40) {
        return -1; // 发现收到的UDP数据不足 40 字节, 则返回错误码 -1
    }
    memcpy(thiz->src_host_id, incoming_bytes, 20);
    memcpy(thiz->dst_host_id, incoming_bytes + 20, 20);
    ssize_t n = total_received - 40;
    if (n > maxdatalen) {
        n = maxdatalen;
    }
    memcpy(data, incoming_bytes + 40, n);
    return n;
}

/* 函数 xsock_sendto(): 按照新范式报文格式定义, 对所有数据包插入40字节主机ID编码 */
ssize_t xsock_sendto(xsock_t *thiz, int sockfd, const void *data, size_t dlen, int sockflags,
        const struct sockaddr *remote_addr, socklen_t addrlen)
{
    char outgoing[1472]; //此处写死最大允许发包的字节数(1472=1500-20-8)
    size_t remain = sizeof(outgoing);
    memcpy(outgoing, thiz->src_host_id, 20);
    memcpy(outgoing + 20, thiz->dst_host_id, 20);
    remain -= 40;
    /* 此处强制截断长包, 舍弃 data 末尾超过 remain(=1432字节)的部分 */
    if (dlen > remain) {
        dlen = remain;
    }
    memcpy(outgoing + 40, data, dlen);
    return sendto(sockfd, outgoing, dlen + 40, sockflags, remote_addr, addrlen) - 40;
}

/* 设置源主机ID */
void xsock_set_src_host_id(xsock_t *thiz, const unsigned char src_host_id[XFS_HOST_ID_SIZE])
{
    memcpy(thiz->src_host_id, src_host_id, XFS_HOST_ID_SIZE);
}

/* 设置目标ID */
void xsock_set_dst_host_id(xsock_t *thiz, const unsigned char dst_host_id[XFS_HOST_ID_SIZE])
{
    memcpy(thiz->dst_host_id, dst_host_id, XFS_HOST_ID_SIZE);
}

/* 擦除源主机ID和目标主机ID */
void xsock_erase_host_ids(xsock_t *thiz)
{
    memset(thiz->src_host_id, 0x00, XFS_HOST_ID_SIZE);
    memset(thiz->dst_host_id, 0x00, XFS_HOST_ID_SIZE);
}
