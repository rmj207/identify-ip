#ifndef __MY_QUEUE__
#define __MY_QUEUE__

struct my_queue;
typedef struct my_queue my_queue_t;

my_queue_t *new_queue(void);
void *my_queue_pop(my_queue_t *);
void *my_queue_pop_timed(my_queue_t *, uint32_t);
void *my_queue_push(my_queue_t *, void *);
void destroy_queue(my_queue_t *);
#endif
