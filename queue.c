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

#include <assert.h>
#include <string.h>

#include "queue.h"

/** @defgroup queue queue
 *
 *  A thread safe FIFO queue.
 *
 *  A queue is a thread safe FIFO queue.  It accepts a pointer to any data,
 *  along with its size, and returns that data upon request.  It holds up to
 *  QUEUE_SIZE data pointers.
 */

/** Initializes a queue.
 *  Clears a new queue, sets it to empty, makes it active, and sets up its
 *  thread mutex and contexts.
 *
 *  @param[in] q The queue to initialize.
 */
void queue_init(queue *q) {
    /* Clear the structure */
    memset(q, 0, sizeof(queue));

    /* Set defaults */
    q->empty = 1;
    q->state = QUEUE_STATE_ACTIVE;

    /* Initialize pthread objects */
    pthread_mutex_init(&(q->mut), NULL);
    pthread_cond_init(&(q->not_full), NULL);
    pthread_cond_init(&(q->not_empty), NULL);
}


/** Destroys a queue structure.
 *  Clears a queue struct, sets it to empty, makes it inactive, and destroys its
 *  thread mutex and contexts.  The queue must not be active and must be empty.
 *
 *  @param[in] q The queue to destroy.
 */
void queue_destroy(queue *q) {
    /* Sanity check */
    assert(q->state == QUEUE_STATE_STOPPED);
    assert(q->empty == 1);

    /* Destroy pthread objects */
    pthread_mutex_destroy(&(q->mut));
    pthread_cond_destroy(&(q->not_full));
    pthread_cond_destroy(&(q->not_empty));

    /* Clear the structure */
    memset(q, 0, sizeof(queue));

    /* Set defaults */
    q->empty = 1;
    q->state = QUEUE_STATE_STOPPED;
}


/** Add data to the queue.
 *  Adds the data pointer and size of the data to the queue.  The queue must be
 *  active, the size must be greater than 0 and it can not be full.
 *
 *  @param[in] q    The queue to add to.
 *  @param[in] in   The data to push onto the stack.
 *  @param[in] size The size of the data value.
 */
void queue_push(queue *q, void *in, size_t size) {
    /* Sanity check */
    assert(size > 0);
    assert(q->state == QUEUE_STATE_ACTIVE);
    assert(q->full == 0);

    /* Push data onto the end of the queue */
    q->stack[q->tail] = in;
    q->stack_sizes[q->tail] = size;

    /* Advance the tail */
    q->tail++;
    if (q->tail == QUEUE_SIZE) {
        q->tail = 0;
    }

    /* Check if the queue is full */
    if (q->tail == q->head) {
        q->full = 1;
    }

    /* It is not empty anymore */
    q->empty = 0;
}


/** Remove data from the queue.
 *  Removes the next data pointer and size of the data from the queue.  The
 *  queue must not be stopped and can not be empty.
 *
 *  @param[in]  q    The queue to add to.
 *  @param[out] out  The data to return.
 *  @param[out] size The size of the data value.
 */
void queue_pop(queue *q, void **out, size_t *size) {
    /* Sanity check */
    assert(q->state != QUEUE_STATE_STOPPED);
    assert(q->empty == 0);

    /* Pop data off the head of the queue */
    *out = q->stack[q->head];
    *size = q->stack_sizes[q->head];

    /* Clear the queue position */
    q->stack[q->head] = NULL;
    q->stack_sizes[q->head] = 0;

    /* Advance the head */
    q->head++;
    if (q->head == QUEUE_SIZE) {
        q->head = 0;
    }

    /* Check if the queue is empty */
    if (q->head == q->tail) {
        q->empty = 1;

        /* Stop the queue */
        if (q->state == QUEUE_STATE_STOPPING) {
            q->state = QUEUE_STATE_STOPPED;
        }
    }

    /* It is not full anymore */
    q->full = 0;
}


/** Stop the queue.
 *  Stops an active queue, this prevents new data from being added.  The queue
 *  must not already be stopped.
 *
 *  @param[in] q The queue to stop.
 */
void queue_stop(queue *q) {
    /* Change state, unless the queue is already stopped */
    if (q->state != QUEUE_STATE_STOPPED) {
        if (q->empty) {
            q->state = QUEUE_STATE_STOPPED;
        } else {
            q->state = QUEUE_STATE_STOPPING;
        }
    }
}

