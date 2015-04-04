#include<pthread.h>
#include<sys/time.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<glib/glib.h>
#include<errno.h>

struct args {
    struct my_queue* queue;
    int id;
};

struct my_queue {
    GQueue *que;
    pthread_mutex_t *que_lock;
    pthread_cond_t *que_cond;
};

struct my_queue *new_queue(void) {
    struct my_queue *new = malloc(sizeof(struct my_queue));
    new->que = g_queue_new();
    new->que_lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(new->que_lock, NULL);
    new->que_cond = malloc(sizeof(pthread_cond_t));
    pthread_cond_init(new->que_cond, NULL);

    return new;
}

void *my_queue_pop(struct my_queue *queue)
{
    void *popped = NULL;
    pthread_mutex_lock(queue->que_lock);
    while (!g_queue_get_length(queue->que)) {
        pthread_cond_wait(queue->que_cond, queue->que_lock);
    }
    popped = g_queue_pop_tail(queue->que);
    pthread_mutex_unlock(queue->que_lock);
    return popped;
}

void *my_queue_pop_timed(struct my_queue *queue, uint32_t timeout)
{
    void *popped = NULL;
    struct timeval now;
    struct timespec wait_time;
    int r = 0;

    gettimeofday(&now, NULL);
    wait_time.tv_sec = now.tv_sec + timeout;
    wait_time.tv_nsec = now.tv_usec;

    pthread_mutex_lock(queue->que_lock);
    while (!g_queue_get_length(queue->que)) {
        if (r == ETIMEDOUT) break;
        r = pthread_cond_timedwait(queue->que_cond, queue->que_lock, &wait_time);
    }
    popped = g_queue_pop_tail(queue->que);
    pthread_mutex_unlock(queue->que_lock);
    return popped;
}

void my_queue_push(struct my_queue *queue, void* to_store)
{
    pthread_mutex_lock(queue->que_lock);
    g_queue_push_head(queue->que, to_store);
    pthread_cond_signal(queue->que_cond);
    pthread_mutex_unlock(queue->que_lock);
}

void destroy_queue(struct my_queue *to_free)
{
    g_queue_free_full(to_free->que, free);
    pthread_mutex_destroy(to_free->que_lock);
    pthread_cond_destroy(to_free->que_cond);
}
