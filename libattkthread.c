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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libattkthread.h"
#include "queue.h"
#include "../config.h"

/** @defgroup libattkthread libattkthread
 *
 *  A threaded attack library.
 *
 *  libatkthread is a file based, threaded attack library template. It consists
 *  of a series of functions that are meant to be extended to create a specific
 *  attack library.
 */

/** Arguments for a client thread.
 *  The arguments for attack client threads.
 */
struct attack_t_args {
    attack_st *attk_st;   /**< The main thread's argument list. */
    queue q;              /**< The queue.                       */
};


/** A client thread.
 *  Attack client thread, removes a block of records from the queue and
 *  processes them, calling attack_check for each record.
 *
 *  @param[in] fargs The attack client thread arguments.
 *
 *  @return          Returns 0 on success, otherwise an error code.
 */
void *attack_client_t(void *fargs) {
    struct attack_t_args *arg_list; /* passed argument                       */
    attack_st *attk_st;             /* main attack_st                        */
    file_st *file_in;               /* input file structure                  */
    file_st *file_out;              /* output file structure                 */
    char *fout_buf;                 /* output file buffer                    */
    size_t fout_buf_size;           /* size of output file buffer            */
    char *fout_buf_p;               /* output file buffer pointer            */
    queue *q;                       /* data queue                            */
    char *buf = NULL;               /* record buffer                         */
    size_t buf_size;                /* size of the buffer                    */
    size_t buf_p;                   /* current buffer position               */
    char *record;                   /* an individual record                  */
    char *result;                   /* The result buffer                     */
    uint64_t records_tested;        /* records tested for the current block  */
    struct timespec ts;             /* conditional timeout                   */
    int check_retval;               /* attack check return value             */
    int free_block_retval;          /* input file free_block return value    */
    int fout_retval;                /* file out return value                 */

    #ifdef DEBUG
    printf("attack_client_t: START (%p)\n", pthread_self());
    #endif

    /* Set defaults */
    arg_list = (struct attack_t_args *)fargs;
    attk_st = arg_list->attk_st;
    file_in = attk_st->file_in;
    if (attk_st->file_out != NULL) {
        file_out = attk_st->file_out;
        fout_buf_size = file_out->record_size * file_in->records_per_block;
        fout_buf = malloc(fout_buf_size);
        memset(fout_buf, 0, fout_buf_size);
        fout_buf_p = fout_buf;
    }
    q = &(arg_list->q);
    check_retval = E_ATTK_RECORD_INVALID;

    /* Set the result buffer to be the same size as a record */
    #ifdef DEBUG
    printf("New result buffer size %i \n", file_in->record_size);
    #endif
    result = malloc(file_in->record_size);
    memset(result, 0, file_in->record_size);

    /* Loop while the queue is active, grabbing blocks of records from the
       queue and checking each record.*/
    while (q->state != QUEUE_STATE_STOPPED) {
        /* Get a record block from the queue */
        pthread_mutex_lock(&(q->mut));
        while (q->empty && q->state != QUEUE_STATE_STOPPED) {
            /* Wait for the queue to have something, or for
               QUEUE_EMPTY_WAIT_SEC seconds */
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += QUEUE_EMPTY_WAIT_SEC;
            pthread_cond_timedwait(&(q->not_empty), &(q->mut), &ts);
            continue; /* We still need to make sure the queue is not empty */
        }

        if (q->state == QUEUE_STATE_STOPPED) {
            /* Time to shut down */
            pthread_mutex_unlock(&(q->mut));
            break;
        } else {
            /* Grab a record block */
            queue_pop(q, (void **)&buf, &buf_size);
            pthread_mutex_unlock(&(q->mut));
            pthread_cond_signal(&(q->not_full));

            /* Loop over the record buffer one record at a time */
            buf_p = records_tested = 0;
            while (buf_p < buf_size) {
                /* Get the next record */
                record = (char *)(buf + buf_p);
                buf_p += file_in->record_size;

                /* Check the record */
                if (attk_st->file_out != NULL) {
                    check_retval = attk_st->attack_check(
                        record,
                        file_in->record_size,
                        fout_buf_p,
                        file_out->record_size,
                        attk_st->attack_data
                    );
                } else {
                    check_retval = attk_st->attack_check(
                        record,
                        file_in->record_size,
                        NULL,
                        0,
                        attk_st->attack_data
                    );
                }

                if (check_retval != E_ATTK_RECORD_INVALID) {
                    /* Update records tested */
                    records_tested += 1;

                    /* Advance the file out pointer */
                    if (attk_st->file_out != NULL) {
                        fout_buf_p += file_out->record_size;

                        /* Is the file out buffer full? */
                        if (fout_buf_p >=
                            (fout_buf + fout_buf_size)) {
                            pthread_mutex_lock(&(file_out->mut));
                            fout_retval = file_out->next_block(
                                file_out,
                                &fout_buf,
                                fout_buf_size
                            );
                            if (fout_retval < 0) {
                                /* Set an error */
                                pthread_mutex_lock(&(attk_st->mut));
                                assert(attk_st->error == 0);
                                attk_st->error = fout_retval;
                                attk_st->e_state = E_STATE_OUTPUT_FILE;
                                pthread_mutex_unlock(&(attk_st->mut));

                                /* Stop the queue */
                                pthread_mutex_lock(&(q->mut));
                                queue_stop(q);
                                pthread_mutex_unlock(&(q->mut));

                                break;
                            }
                            pthread_mutex_unlock(&(file_out->mut));
                            memset(fout_buf, 0, fout_buf_size);
                            fout_buf_p = fout_buf;
                        }
                    }

                    if (check_retval == 0) {
                        /* We have the answer! */
                        #ifdef DEBUG
                        printf("Answer found: (%s) (%i)\n", record,
                               file_in->record_size);
                        #endif
                        memcpy(result, record, file_in->record_size);

                        /* Stop processing the current read block */
                        break;
                    }
                }
            }

            /* Update the records tested counter */
            pthread_mutex_lock(&(attk_st->mut));
            attk_st->_s.records_tested += records_tested;
            pthread_mutex_unlock(&(attk_st->mut));

            /* Free the record block */
            pthread_mutex_lock(&(file_in->mut));
            free_block_retval = file_in->free_block(file_in, buf, buf_size);
            pthread_mutex_unlock(&(file_in->mut));
            if (free_block_retval != 0) {
                /* Set an error */
                pthread_mutex_lock(&(attk_st->mut));
                assert(attk_st->error == 0);
                attk_st->error = free_block_retval;
                attk_st->e_state = E_STATE_INPUT_FILE;
                pthread_mutex_unlock(&(attk_st->mut));

                /* Stop the queue */
                pthread_mutex_lock(&(q->mut));
                queue_stop(q);
                pthread_mutex_unlock(&(q->mut));

                break;
            }

            if (check_retval == 0) {
                /* We have the answer! - Stop processing the queue */
                break;
            }
        }
    }

    /* Write out any remaining file output buffer contents */
    if (attk_st->file_out != NULL) {
        if (fout_buf_p > fout_buf) {
            pthread_mutex_lock(&(file_out->mut));
            fout_retval = file_out->next_block(file_out, &fout_buf,
                                               fout_buf_p - fout_buf);
            if (fout_retval < 0) {
                /* Set an error */
                pthread_mutex_lock(&(attk_st->mut));
                assert(attk_st->error == 0);
                attk_st->error = fout_retval;
                attk_st->e_state = E_STATE_OUTPUT_FILE;
                pthread_mutex_unlock(&(attk_st->mut));

                /* Stop the queue */
                pthread_mutex_lock(&(q->mut));
                queue_stop(q);
                pthread_mutex_unlock(&(q->mut));
            }
            pthread_mutex_unlock(&(file_out->mut));
        }
        free(fout_buf);
    }

    /* Set the answer, if we have it */
    if (check_retval == 0) {
        /* Update result status */
        pthread_mutex_lock(&(attk_st->mut));
        if (attk_st->_s.result_size == 0) {
            attk_st->_s.result = result;
            attk_st->_s.result_size = file_in->record_size;
        } else {
            /* We already have an answer, free the result buffer */
            free(result);
        }
        pthread_mutex_unlock(&(attk_st->mut));

        /* Stop the queue */
        pthread_mutex_lock(&(q->mut));
        queue_stop(q);
        pthread_mutex_unlock(&(q->mut));
    } else {
        /* No answer, free the result buffer */
        free(result);
    }

    return NULL;
}


/** The main attack thread.
 *  This thread manages the client threads, refills the block queue, looks for a
 *  result, cleans up everything when done, and, finally, calls the callback.
 *
 *  @param[in] fargs The main attack thread arguments.
 *
 *  @return          Returns 0 on success, otherwise an error code.
 */
void *attack_main_t(void *fargs) {
    attack_st *attk_st;                 /* main attack_st                     */
    file_st *file_in;                   /* input file structure               */
    file_st *file_out;                  /* output file structure              */
    queue *q;                           /* data queue                         */
    struct attack_t_args t_args;        /* client thread arguments            */
    int i;                              /* generic counter                    */
    pthread_t client_t[MAX_THREADS];    /* client threads                     */
    char *buf;                          /* record buffer                      */
    ssize_t buf_size;                   /* record buffer size                 */
    char *temp_buf;                     /* temporary buffer                   */
    size_t temp_size;                   /* temporary buffer size              */
    struct timespec ts;                 /* conditional timeout                */
    int in_file_retval;                 /* input open file return value       */
    int out_file_retval;                /* output open file return value      */
    int free_block_retval;              /* file free_block return value       */
    int total_records;                  /* Temporary holder for total records */

    #ifdef DEBUG
    printf("attack_main_t: START (%p)\n", pthread_self());
    #endif

    /* Set arguments */
    attk_st = (attack_st *)fargs;
    file_in = attk_st->file_in;
    file_out = attk_st->file_out;
    t_args.attk_st = attk_st;
    q = &(t_args.q);
    in_file_retval = out_file_retval = 0;

    /* Create the queue */
    queue_init(q);

    /* Start the threads */
    assert(attk_st->threads <= MAX_THREADS);
    for (i = 0; i < attk_st->threads; i++) {
        pthread_create(&client_t[i], NULL, attack_client_t, (void *)&t_args);
    }

    /* Open the input file */
    pthread_mutex_lock(&(file_in->mut));
    in_file_retval = file_in->open_file(file_in);
    total_records = file_in->total_records;
    pthread_mutex_unlock(&(file_in->mut));
    if (in_file_retval != 0) {
        /* Set an error and stop the attack */
        pthread_mutex_lock(&(attk_st->mut));
        assert(attk_st->error == 0);
        attk_st->error = in_file_retval;
        attk_st->e_state = E_STATE_INPUT_FILE;
        pthread_mutex_unlock(&(attk_st->mut));
        stop_attack(attk_st);
    } else {
        pthread_mutex_lock(&(attk_st->mut));
        attk_st->_s.total_records += total_records;
        pthread_mutex_unlock(&(attk_st->mut));
    }

    /* Open the output file */
    if (attk_st->state == ATTACK_STATE_ACTIVE && file_out != NULL) {
        pthread_mutex_lock(&(file_out->mut));
        out_file_retval = file_out->open_file(file_out);
        pthread_mutex_unlock(&(file_out->mut));
        if (out_file_retval != 0) {
            /* Set an error and stop the attack */
            pthread_mutex_lock(&(attk_st->mut));
            assert(attk_st->error == 0);
            attk_st->error = out_file_retval;
            attk_st->e_state = E_STATE_OUTPUT_FILE;
            pthread_mutex_unlock(&(attk_st->mut));
            stop_attack(attk_st);
        }
    }

    /* Add blocks to the queue */
    while (attk_st->state == ATTACK_STATE_ACTIVE) {
        buf = NULL;
        buf_size = 0;

        /* Get the next block */
        pthread_mutex_lock(&(file_in->mut));
        buf_size = file_in->next_block(file_in, &buf, 0);
        pthread_mutex_unlock(&(file_in->mut));
        if (buf_size < 0) {
            /* Set an error and stop the attack */
            pthread_mutex_lock(&(attk_st->mut));
            assert(attk_st->error == 0);
            attk_st->error = buf_size;
            attk_st->e_state = E_STATE_INPUT_FILE;
            pthread_mutex_unlock(&(attk_st->mut));
            break;
        } else if (buf_size == 0) {
            /* No more pieces */
            break;
        }

        /* Add the block to the queue */
        pthread_mutex_lock(&(q->mut));
        while (q->full && q->state == QUEUE_STATE_ACTIVE) {
            /* Wait for the queue to have free space, or for
               QUEUE_EMPTY_WAIT_SEC seconds */
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += QUEUE_FULL_WAIT_SEC;
            pthread_cond_timedwait(&(q->not_full), &(q->mut), &ts);
            continue; /* We still need to make sure the queue is not full */
        }
        if (q->state != QUEUE_STATE_ACTIVE) {
            /* Queue is inactive, time to stop */
            pthread_mutex_unlock(&(q->mut));

            /* Free the block */
            free_block_retval = file_in->free_block(file_in, buf, buf_size);
            if (free_block_retval != 0) {
                /* Set an error */
                assert(attk_st->error == 0);
                attk_st->error = free_block_retval;
                attk_st->e_state = E_STATE_INPUT_FILE;
            }

            /* Stop the attack */
            break;
        } else {
            /* Add a record block */
            queue_push(q, buf, buf_size);
            pthread_mutex_unlock(&(q->mut));
            pthread_cond_signal(&(q->not_empty));
        }
    }

    /* Stop the attack */
    #ifdef DEBUG
    printf("attack_main_t: stopping attack\n");
    #endif
    stop_attack(attk_st);

    /* Stop the queue */
    #ifdef DEBUG
    printf("attack_main_t: stopping queue\n");
    #endif
    pthread_mutex_lock(&(q->mut));
    queue_stop(q);
    pthread_mutex_unlock(&(q->mut));

    /* Check and see if we have an answer */
    #ifdef DEBUG
    printf("attack_main_t: checking for answer\n");
    #endif
    pthread_mutex_lock(&(attk_st->mut));
    temp_size = attk_st->_s.result_size;
    pthread_mutex_unlock(&(attk_st->mut));
    if (temp_size > 0) {
        /* We do have an answer, lets clear the queue */
        pthread_mutex_lock(&(q->mut));
        while (q->empty == 0) {
            queue_pop(q, (void **)&temp_buf, &temp_size);
            free_block_retval = file_in->free_block(file_in, temp_buf,
                                                    temp_size);
            if (free_block_retval != 0) {
                /* Set an error */
                assert(attk_st->error == 0);
                attk_st->error = free_block_retval;
                attk_st->e_state = E_STATE_INPUT_FILE;
            }
        }
        pthread_mutex_unlock(&(q->mut));
    }

    /* Wait for the threads to finish */
    for (i = 0; i < attk_st->threads; i++) {
        pthread_join(client_t[i], NULL);
    }

    /* Make sure the queue is clear */
    pthread_mutex_lock(&(q->mut));
    while (q->empty == 0) {
        queue_pop(q, (void **)&temp_buf, &temp_size);
        free_block_retval = file_in->free_block(file_in, temp_buf, temp_size);
        if (free_block_retval != 0) {
            /* Set an error */
            assert(attk_st->error == 0);
            attk_st->error = free_block_retval;
            attk_st->e_state = E_STATE_INPUT_FILE;
        }
    }
    pthread_mutex_unlock(&(q->mut));

    /* Destroy the queue */
    queue_destroy(q);

    /* Close the input file */
    if (in_file_retval == 0) {
        in_file_retval = file_in->close_file(file_in);
        if (in_file_retval != 0) {
            /* Set an error */
            pthread_mutex_lock(&(attk_st->mut));
            assert(attk_st->error == 0);
            attk_st->error = in_file_retval;
            attk_st->e_state = E_STATE_INPUT_FILE;
            pthread_mutex_unlock(&(attk_st->mut));
        }
    }

    /* Close the output file */
    if (file_out != NULL && out_file_retval == 0) {
        out_file_retval = file_out->close_file(file_out);
        if (out_file_retval != 0) {
            /* Set an error */
            pthread_mutex_lock(&(attk_st->mut));
            assert(attk_st->error == 0);
            attk_st->error = out_file_retval;
            attk_st->e_state = E_STATE_OUTPUT_FILE;
            pthread_mutex_unlock(&(attk_st->mut));
        }
    }

    /* Call the callback */
    #ifdef DEBUG
    printf("attack_main_t: calling callback\n");
    #endif
    attk_st->callback(attk_st);

    attk_st->state = ATTACK_STATE_STOPPED;

    return NULL;
}


/** Initialize attack_st.
 *  Initialize an attack_st structure.
 *
 *  @param[in] attk_st      The attack object.
 *  @param[in] file_in      A file structure to read records from.
 *  @param[in] file_out     A file structure to write records to, NULL if no
 *                          output.
 *  @param[in] threads      Number of client threads to use.
 *  @param[in] attack_check Function to call for each word.
 *  @param[in] callback     Callback when main thread completes.
 *  @param[in] attack_data  Data used by attack_check to check word.
 *
 *  @return                 Returns 0 on success, otherwise an error code.
 */
int attack_st_init(attack_st *attk_st, file_st *file_in, file_st *file_out,
                   uint16_t threads, int (*attack_check)(char *record,
                                                         size_t record_size,
                                                         char *ret_record,
                                                         size_t return_size,
                                                         void *attack_data),
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, void *attack_data) {
    #ifdef DEBUG
    printf("attack_st_init: START %p|%p|%p|%i|%p|%p|%p|%p\n", attk_st, file_in,
           file_out, threads, attack_check, callback, callback_data,
           attack_data);
    #endif

    /* Reset structure */
    memset(attk_st, 0, sizeof(attack_st));

    /* Set number of client threads to use */
    if (threads == 0) {
        attk_st->threads = 1;
    } else {
        attk_st->threads = threads;
    }

    /* Set attributes */
    attk_st->file_in = file_in;
    attk_st->file_out = file_out;
    attk_st->attack_check = attack_check;
    attk_st->callback = callback;
    attk_st->callback_data = callback_data;
    attk_st->attack_data = attack_data;

    /* Initialize status mutex */
    pthread_mutex_init(&(attk_st->mut), NULL);

    return 0;
}


/** Destroy attack_st.
 *  Destroy an attack_st structure.
 *
 *  @param[in] attk_st  The attack object.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int attack_st_destroy(attack_st *attk_st) {
    #ifdef DEBUG
    printf("attack_st_destroy: START\n");
    #endif

    /* Free any stored result */
    if (attk_st->_s.result != NULL && attk_st->_s.result_size > 0) {
        free(attk_st->_s.result);
    }
    memset(&(attk_st->_s), 0, sizeof(attk_st->_s));

    /* Destroy the main thread mutex */
    return pthread_mutex_destroy(&(attk_st->mut));

    /* The attack is over */
    attk_st->state = ATTACK_STATE_STOPPED;
}


/** Start an attack.
 *  This will start the main thread with the passed attack_st structure.  If
 *  callback is not NULL it will call callback when the main thread ends.
 *
 *  @param[in] attk_st  The attack object.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int start_attack(attack_st *attk_st) {
    #ifdef DEBUG
    printf("start_attack: START\n");
    #endif

    /* Start the main thread */
    attk_st->state = ATTACK_STATE_ACTIVE;
    return pthread_create(&(attk_st->main), NULL, attack_main_t,
                          (void *)attk_st);
}


/** Start an attack.
 *  This will start the main thread with the passed attack_st structure.  If
 *  callback is not NULL it will call callback when the main thread ends.
 *
 *  @param[in] attk_st          The attack object.
 *  @param[in] callback         Callback when main thread completes.
 *  @param[in] callback_data    Data to save for callback function.
 *
 *  @return                     Returns 0 on success, otherwise an error code.
 */
int start_attack_c(attack_st *attk_st,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data) {
    #ifdef DEBUG
    printf("start_attack_c: START\n");
    #endif

    /* Setup the callback */
    attk_st->callback = callback;
    attk_st->callback_data = callback_data;

    /* Call start_attack */
    return start_attack(attk_st);
}


/** Get the status of an attack.
 *  Sets status to a copy of the current status. If result is not null also
 *  returns a copy of the result buffer.  status.result must be a buffer of
 *  status.result_size size, if there is no result to copy then
 *  status.result_size is set to 0.
 *
 *  @param[in]  attk_st The attack object.
 *  @param[out] status  The status object to fill.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int check_attack(attack_st *attk_st, attack_status *status) {
    int ret_val;
    #ifdef DEBUG
    printf("check_attack: START (%p) (%i) (%p)\n", attk_st, attk_st->mut,
           &(attk_st->mut));
    #endif

    if (attk_st->state != ATTACK_STATE_STOPPED) {
        pthread_mutex_lock(&(attk_st->mut));
        status->records_tested = attk_st->_s.records_tested;
        status->total_records = attk_st->_s.total_records;
        if (attk_st->_s.result != NULL) {
            memset(status->result, 0, status->result_size);
            if (attk_st->_s.result_size < status->result_size) {
                status->result_size = attk_st->_s.result_size;
            }
            memcpy(status->result, attk_st->_s.result, status->result_size);
        } else {
            status->result_size = 0;
        }
        pthread_mutex_unlock(&(attk_st->mut));

        return 0;
    } else {
        if (attk_st != NULL) {
            status->records_tested = attk_st->_s.records_tested;
            status->total_records = attk_st->_s.total_records;
            if (attk_st->_s.result != NULL) {
                memset(status->result, 0, status->result_size);
                if (attk_st->_s.result_size < status->result_size) {
                    status->result_size = attk_st->_s.result_size;
                }
                memcpy(status->result, attk_st->_s.result, status->result_size);
            } else {
                status->result_size = 0;
            }
        }

        return E_ATTK_STOPPED;
    }
}


/** Stop an attack.
 *  This will stop an ongoing attack as early as possible.  Callback will still
 *  be called if set.  Returns immediately, does not wait for threads to finish.
 *
 *  @param[in] attk_st  The attack object.
 */
void stop_attack(attack_st *attk_st) {
    #ifdef DEBUG
    printf("stop_attack: START\n");
    #endif

    /* Start shutting down the attack */
    pthread_mutex_lock(&(attk_st->mut));
    if (attk_st->state != ATTACK_STATE_STOPPED) {
        attk_st->state = ATTACK_STATE_STOPPING;
    }
    pthread_mutex_unlock(&(attk_st->mut));
}

