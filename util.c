#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

deque_t *deque_new(void)
{
    deque_t *dp = (deque_t *)malloc(sizeof(deque_t));
    assert(dp);
    deque_init(dp);

    return dp;
}

void deque_init(deque_t *dp)
{
    dp->head = NULL;
    dp->tail = NULL;
}

void deque_deinit(deque_t *dp)
{
    assert(dp);
    while (dp->tail)
        deque_pop(dp);
}

void deque_free(deque_t *dp)
{
    assert(dp);
    deque_deinit(dp);
    free(dp);
}

size_t deque_count(deque_t *dp)
{
    assert(dp);
    size_t n = 0;

    for(deque_item_t *i=dp->head; i; i=i->next)
        ++n;

    return n;
}

void deque_append(deque_t *dp, void *p)
{
    assert(dp);
    deque_item_t *i = (deque_item_t *)malloc(sizeof(deque_item_t));
    assert(i);

    i->p = p;
    i->next = NULL;
    i->prev = dp->tail;

    if (dp->tail)
        dp->tail->next = i;
    else
        dp->head = i;
    dp->tail = i;
}

void *deque_pop(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->tail;
    assert(i);
    void *p = i->p;

    dp->tail = i->prev;
    if (i->prev)
        i->prev->next = NULL;
    else
        dp->head = NULL;
    free(i);

    return p;
}

void *deque_peek(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->tail;
    assert(i);
    void *p = i->p;

    return p;
}

void deque_appendleft(deque_t *dp, void *p)
{
    assert(dp);
    deque_item_t *i = (deque_item_t *)malloc(sizeof(deque_item_t));
    assert(i);

    i->p = p;
    i->next = dp->head;
    i->prev = NULL;

    if (dp->head)
        dp->head->prev = i;
    else
        dp->tail = i;
    dp->head = i;
}

void *deque_popleft(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->head;
    assert(i);
    void *p = i->p;

    dp->head = i->next;
    if (i->next)
        i->next->prev = NULL;
    else
        dp->tail = NULL;
    free(i);

    return p;
}

void *deque_peekleft(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->head;
    assert(i);
    void *p = i->p;

    return p;
}

void deque_remove(deque_t *dp, deque_item_t *dip)
{
    assert(dp);
    assert(dip);

    if (dip->prev)
    {
        assert(dip->prev->next == dip);
        dip->prev->next = dip->next;
    }
    else
    {
        assert(dp->head == dip);
        dp->head = dip->next;
    }
    if (dip->next)
    {
        assert(dip->next->prev == dip);
        dip->next->prev = dip->prev;
    }
    else
    {
        assert(dp->tail == dip);
        dp->tail = dip->prev;
    }

    free(dip);
}


buffer_t *buffer_new(int cap)
{
    assert(cap>0);
    buffer_t *bp = (buffer_t *)malloc(sizeof(buffer_t)+cap);
    assert(bp);

    buffer_init(bp, cap);

    return bp;
}

void buffer_init(buffer_t *bp, int cap)
{
    bp->cap = cap;
    bp->len = 0;
}

void buffer_free(buffer_t *bp)
{
    free(bp);
}

int buffer_eq(buffer_t *a, buffer_t *b)
{
    if (a->len == b->len)
    {
        const int n = a->len;
        for (int i=0; i<n; ++i)
            if (a->buf[i] != b->buf[i])
                return 0;
        return 1;
    }
    return 0;
}

void dump_addr(struct sockaddr *sa, const char *indent)
{
    fprintf(stderr, "%s%s\n", indent, sdump_addr(sa));
}

const char *sdump_addr(struct sockaddr *sa)
{
    static char buf[1024];

    switch (sa->sa_family)
    {
        case AF_INET:
            memmove(buf, "INET: ", 6);
            inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf+6, sizeof(buf)-6);
            sprintf(buf+strlen(buf), ":%d", ntohs(((struct sockaddr_in *)sa)->sin_port));
            break;
        case AF_INET6:
            memmove(buf, "INET6: [", 8);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf+8, sizeof(buf)-8);
            sprintf(buf+strlen(buf), "]:%d", ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
            break;
        default:
            memmove(buf, "unknown", 8);
            break;
    }

    return buf;
}
