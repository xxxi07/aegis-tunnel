/*
 * threadpool.h — Simple fixed-size thread pool
 *
 * Replaces fork() per connection with pre-spawned worker threads.
 * Much lighter weight: no process creation, shared memory, faster
 * context switch than fork+exec.
 *
 * Usage:
 *   threadpool_t *tp = threadpool_create(8);   // 8 worker threads
 *   threadpool_submit(tp, worker_func, &arg);  // non-blocking submit
 *   threadpool_shutdown(tp);                   // wait & cleanup
 */
#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>

/* Work item: function + argument */
typedef void (*threadpool_work_fn)(void *arg);

typedef struct threadpool_work_t {
    threadpool_work_fn fn;
    void              *arg;
    struct threadpool_work_t *next;
} threadpool_work_t;

/* Thread pool */
typedef struct {
    pthread_t       *threads;
    int              num_threads;
    int              shutdown;

    pthread_mutex_t  mutex;
    pthread_cond_t   cond;
    threadpool_work_t *head;
    threadpool_work_t *tail;
    int              pending;
} threadpool_t;

/* Create a thread pool with `nthreads` workers */
threadpool_t *threadpool_create(int nthreads);

/* Submit work (non-blocking, returns 0 on success) */
int  threadpool_submit(threadpool_t *tp, threadpool_work_fn fn, void *arg);

/* Wait for all pending work, then destroy pool */
void threadpool_shutdown(threadpool_t *tp);

/* Get number of pending work items */
int  threadpool_pending(threadpool_t *tp);

#endif /* THREADPOOL_H */
