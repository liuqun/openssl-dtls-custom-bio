#ifndef XSOCK_H_
#define XSOCK_H_

#include <sys/socket.h> // sockaddr

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct xsock_t_ {
    unsigned char src_host_id[20]; /// 通讯发起者(源主机)的主机编码
    unsigned char dst_host_id[20]; /// 目标主机编码
    int sockfd; /// socket fd: 有效取值>=3表示正常套接字编号, 负数表示套接字打开失败或套接字尚未打开
};
typedef struct xsock_t_ xsock_t;

#define XFS_HOST_ID_SIZE 20
#define XFS_SRC_HOST_ID_SIZE 20
#define XFS_DST_HOST_ID_SIZE 20
#define XFS_XUDP_LAYER_HEADER_LENGTH (XFS_SRC_HOST_ID_SIZE+XFS_DST_HOST_ID_SIZE) // 共20+20=40字节报头

extern void xsock_set_sockfd(xsock_t *thiz, int sockfd);
extern void xsock_set_src_host_id(xsock_t *thiz, const unsigned char src_host_id[XFS_HOST_ID_SIZE]);
extern void xsock_set_dst_host_id(xsock_t *thiz, const unsigned char dst_host_id[XFS_HOST_ID_SIZE]);
extern void xsock_erase_host_ids(xsock_t *thiz);

extern ssize_t xsock_sendto(xsock_t *thiz, /// xsock对象的this指针
        const void *data, /// 指向待发送数据
        size_t dlen, /// 即 data length
        int flags, /// (暂时用不到)
        const struct sockaddr *remote_addr, /// 对端IP和端口号
        socklen_t addrlen /// IPv4地址(或IPv6)加端口号的总长度
        );

extern ssize_t xsock_recvfrom(xsock_t *thiz, /// xsock对象的this指针
        unsigned char data[], /// 指向预先分配的内存空间, 用于存放即将接收到的数据
        size_t maxdatalen, /// 预分配空间总字节数
        int flags, /// 取值可以等于 MSG_PEEK 表示尝试取数据包时不清空内核协议栈中的数据包原始缓存
        struct sockaddr *remote_addr, /// 作为输出参数: 对端IP和端口号
        socklen_t *addrlen /// 作为输出参数: IPv4地址(或IPv6)加端口号的总长度
        );

#define xsock_recv(thiz, data, maxdatalen, flags) \
    xsock_recvfrom((thiz), (data), (maxdatalen), (flags), NULL, NULL)


#ifdef __cplusplus
}
#endif // __cplusplus
#endif // XSOCK_H_
