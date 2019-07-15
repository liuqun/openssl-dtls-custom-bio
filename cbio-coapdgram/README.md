# 参考 libcoap2 学习如何创建 custom BIO

本目录存放了开源项目 libcoap2 中基于 OpenSSL API 实现的 DTLS 功能。

# coap_openssl.c
libcoap2 项目中定义的 custom BIO 位于源文件 `coap_openssl.c` 中。

# 新增自定义的 custom BIO_METHOD
```
//void *coap_dtls_new_context(struct coap_context_t *coap_context)
//{
    //...
    context->dtls.meth = BIO_meth_new(BIO_TYPE_DGRAM, "coapdgram");
    if (!context->dtls.meth)
      goto error;
    context->dtls.bio_addr = BIO_ADDR_new();
    if (!context->dtls.bio_addr)
      goto error;
    BIO_meth_set_write(context->dtls.meth, coap_dgram_write);
    BIO_meth_set_read(context->dtls.meth, coap_dgram_read);
    BIO_meth_set_puts(context->dtls.meth, coap_dgram_puts);
    BIO_meth_set_ctrl(context->dtls.meth, coap_dgram_ctrl);
    BIO_meth_set_create(context->dtls.meth, coap_dgram_create);
    BIO_meth_set_destroy(context->dtls.meth, coap_dgram_destroy);
    //...
//}
```

## 内部数据结构体 `coap_ssl_data` 的定义
```
#include "coap2/coap.h"
#include "coap2/coap_session.h"
#include "coap2/coap_time.h"

typedef struct coap_ssl_st {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned peekmode;
  coap_tick_t timeout;
} coap_ssl_data;

static int coap_dgram_create(BIO *a) {
  coap_ssl_data *data = NULL;
  data = malloc(sizeof(coap_ssl_data));
  if (data == NULL)
    return 0;
  BIO_set_init(a, 1);
  BIO_set_data(a, data);
  memset(data, 0x00, sizeof(coap_ssl_data));
  return 1;
}
```

## 实现 BIO_s_custom_read() 函数（即coap_dgram_read())
代码分析:

coap_dgram_read()函数直接从 coap_ssl_data->pdu 区域中取出若干字节 DTLS 协议报文数据，复制到 out 缓冲区供上层 SSL 对象进行协议解析:

```
static int coap_dgram_read(BIO *a, char *out, int outl)
{
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (out != NULL) {
    if (data != NULL && data->pdu_len > 0) {
      if (outl < (int)data->pdu_len) {
        memcpy(out, data->pdu, outl);
        ret = outl;
      } else {
        memcpy(out, data->pdu, data->pdu_len);
        ret = (int)data->pdu_len;
      }
      if (!data->peekmode) {
        data->pdu_len = 0;
        data->pdu = NULL;
      }
    } else {
      ret = -1;
    }
    BIO_clear_retry_flags(a);
    if (ret < 0)
      BIO_set_retry_read(a);
  }
  return ret;
}
```

## 实现 BIO_s_custom_write() 函数（即coap_dgram_write())
```
static int coap_dgram_write(BIO *a, const char *in, int inl)
{
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (data->session) {
    if (data->session->sock.flags == COAP_SOCKET_EMPTY && data->session->endpoint == NULL) {
      /* socket was closed on client due to error */
      BIO_clear_retry_flags(a);
      return -1;
    }
    ret = (int)coap_session_send(data->session, (const uint8_t *)in, (size_t)inl);
    BIO_clear_retry_flags(a);
    if (ret <= 0)
      BIO_set_retry_write(a);
  } else {
    BIO_clear_retry_flags(a);
    ret = -1;
  }
  return ret;
}
```

# libcoap2 顶层数据结构 coap_context_t
```
#include "coap2/net.h"

/**
 * The CoAP stack's global state is stored in a coap_context_t object.
 */
typedef struct coap_context_t {

  ssize_t (*network_send)(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen);

  ssize_t (*network_read)(coap_socket_t *sock, struct coap_packet_t *packet);

  size_t(*get_client_psk)(const coap_session_t *session, const uint8_t *hint, size_t hint_len, uint8_t *identity, size_t *identity_len, size_t max_identity_len, uint8_t *psk, size_t max_psk_len);
  size_t(*get_server_psk)(const coap_session_t *session, const uint8_t *identity, size_t identity_len, uint8_t *psk, size_t max_psk_len);
  size_t(*get_server_hint)(const coap_session_t *session, uint8_t *hint, size_t max_hint_len);

  void *dtls_context;
  uint8_t *psk_hint;
  size_t psk_hint_len;
  uint8_t *psk_key;
  size_t psk_key_len;

  unsigned int session_timeout;    /**< Number of seconds of inactivity after which an unused session will be closed. 0 means use default. */
  unsigned int max_idle_sessions;  /**< Maximum number of simultaneous unused sessions per endpoint. 0 means no maximum. */
  unsigned int max_handshake_sessions; /**< Maximum number of simultaneous negotating sessions per endpoint. 0 means use default. */
  unsigned int ping_timeout;           /**< Minimum inactivity time before sending a ping message. 0 means disabled. */
  unsigned int csm_timeout;           /**< Timeout for waiting for a CSM from the remote side. 0 means disabled. */

  void *app;                       /**< application-specific data */
} coap_context_t;
```