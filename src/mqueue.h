/* mqueue.h - thread-safe FIFO of heap-allocated strings */
#ifndef NS_MQUEUE_H
#define NS_MQUEUE_H

#include "platform.h"

typedef struct mq_node { char *msg; struct mq_node *next; } mq_node;

typedef struct {
    mq_node *head, *tail;
    ns_mutex lock;
} mqueue;

void  mq_init(mqueue *q);
void  mq_destroy(mqueue *q);
/* takes ownership of `msg` (heap-allocated, freed by mq_pop caller) */
void  mq_push(mqueue *q, char *msg);
/* returns next message (caller frees) or NULL if empty */
char *mq_pop(mqueue *q);

#endif
