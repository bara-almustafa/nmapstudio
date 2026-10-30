#include "mqueue.h"
#include "util.h"
#include <stdlib.h>

void mq_init(mqueue *q) { q->head = q->tail = NULL; ns_mutex_init(&q->lock); }

void mq_destroy(mqueue *q) {
    char *m;
    while ((m = mq_pop(q)) != NULL) free(m);
    ns_mutex_destroy(&q->lock);
}

void mq_push(mqueue *q, char *msg) {
    mq_node *n = xmalloc(sizeof *n);
    n->msg = msg; n->next = NULL;
    ns_mutex_lock(&q->lock);
    if (q->tail) q->tail->next = n; else q->head = n;
    q->tail = n;
    ns_mutex_unlock(&q->lock);
}

char *mq_pop(mqueue *q) {
    ns_mutex_lock(&q->lock);
    mq_node *n = q->head;
    if (n) { q->head = n->next; if (!q->head) q->tail = NULL; }
    ns_mutex_unlock(&q->lock);
    if (!n) return NULL;
    char *m = n->msg;
    free(n);
    return m;
}
