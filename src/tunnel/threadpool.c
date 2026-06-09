/*
 * threadpool.c — Fixed-size thread pool implementation
 */
#include "tunnel/threadpool.h"

#include <stdlib.h>
#include <string.h>

static void *worker_loop(void *arg)
{
    threadpool_t *tp = (threadpool_t *)arg;

    for (;;) {
        pthread_mutex_lock(&tp->mutex);

        /* Wait for work or shutdown */
        while (!tp->shutdown && tp->head == NULL) {
            pthread_cond_wait(&tp->cond, &tp->mutex);
        }

        if (tp->shutdown && tp->head == NULL) {
            pthread_mutex_unlock(&tp->mutex);
            return NULL;
        }

        /* Dequeue work */
        threadpool_work_t *w = tp->head;
        if (w == tp->tail) {
            tp->head = tp->tail = NULL;
        } else {
            tp->head = w->next;
        }
        tp->pending--;
        pthread_mutex_unlock(&tp->mutex);

        /* Execute */
        w->fn(w->arg);
        free(w);
    }
}

threadpool_t *threadpool_create(int nthreads)
{
    threadpool_t *tp = (threadpool_t *)calloc(1, sizeof(*tp));
    if (!tp) return NULL;

    tp->num_threads = nthreads;
    tp->threads = (pthread_t *)calloc((size_t)nthreads, sizeof(pthread_t));
    if (!tp->threads) { free(tp); return NULL; }

    pthread_mutex_init(&tp->mutex, NULL);
    pthread_cond_init(&tp->cond, NULL);

    for (int i = 0; i < nthreads; i++) {
        pthread_create(&tp->threads[i], NULL, worker_loop, tp);
    }

    return tp;
}

int threadpool_submit(threadpool_t *tp, threadpool_work_fn fn, void *arg)
{
    threadpool_work_t *w = (threadpool_work_t *)malloc(sizeof(*w));
    if (!w) return -1;

    w->fn   = fn;
    w->arg  = arg;
    w->next = NULL;

    pthread_mutex_lock(&tp->mutex);
    if (tp->tail) {
        tp->tail->next = w;
    } else {
        tp->head = w;
    }
    tp->tail = w;
    tp->pending++;
    pthread_cond_signal(&tp->cond);
    pthread_mutex_unlock(&tp->mutex);

    return 0;
}

void threadpool_shutdown(threadpool_t *tp)
{
    if (!tp) return;

    pthread_mutex_lock(&tp->mutex);
    tp->shutdown = 1;
    pthread_cond_broadcast(&tp->cond);
    pthread_mutex_unlock(&tp->mutex);

    for (int i = 0; i < tp->num_threads; i++) {
        pthread_join(tp->threads[i], NULL);
    }

    pthread_mutex_destroy(&tp->mutex);
    pthread_cond_destroy(&tp->cond);
    free(tp->threads);
    free(tp);
}

int threadpool_pending(threadpool_t *tp)
{
    int n;
    pthread_mutex_lock(&tp->mutex);
    n = tp->pending;
    pthread_mutex_unlock(&tp->mutex);
    return n;
}
