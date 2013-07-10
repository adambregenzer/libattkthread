/*
 * libattkthread - A threaded attack library template.
 *
 * Copyright (c) 2008-2013, Adam Bregenzer <adam@bregenzer.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * libattkthread is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef QUEUE_H
#define QUEUE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdint.h>

/** @addtogroup queue
 *  @{
 */

#define QUEUE_SIZE      20  /**< Maximum number of pointers a queue can hold. */

/** Queue state enum.
 *  Indicates the state of a queue.
 */
typedef enum {
    QUEUE_STATE_ACTIVE,     /**< Queue active state.   */
    QUEUE_STATE_STOPPING,   /**< Queue stopping state. */
    QUEUE_STATE_STOPPED     /**< Queue stopped state.  */
} queue_state;

/** A queue structure.
 *  A FIFO, pthreads compatible queue.
 */
typedef struct {
    void *stack[QUEUE_SIZE];    /**< The queue data stack.                    */
    size_t stack_sizes[QUEUE_SIZE]; /**< The queue data size stack.           */
    int head;                   /**< Pointer to the head of the queue.        */
    int tail;                   /**< Pointer to the tail of the queue.        */
    int full;                   /**< True if the queue is full.               */
    int empty;                  /**< True if the queue is empty.              */
    queue_state state;          /**< The current state of the queue.          */
    pthread_mutex_t mut;        /**< Thread mutex for the queue.              */
    pthread_cond_t not_full;    /**< Thread condition for the queue being not
                                 *   full.
                                 */
    pthread_cond_t not_empty;   /**< Thread condition for the queue being not
                                 *   empty.
                                 */
} queue;

void queue_init(queue *q);
void queue_destroy(queue *q);
void queue_push(queue *q, void *in, size_t size);
void queue_pop(queue *q, void **out, size_t *size);
void queue_stop(queue *q);

/** @} */

#endif      /* QUEUE_H */

