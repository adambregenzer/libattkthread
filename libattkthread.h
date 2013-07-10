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

#ifndef LIBATTKTHREADING_H
#define LIBATTKTHREADING_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

/** @addtogroup libattkthread
 *  @{
 */

#define QUEUE_EMPTY_WAIT_SEC          1 /**< Seconds to wait while queue is
                                         *   empty before checking to see if
                                         *   the queue is shut down.
                                         */
#define QUEUE_FULL_WAIT_SEC           1 /**< Seconds to wait while queue is
                                         *   full before checking to see if a
                                         *   thread found an answer.
                                         */
#define MAX_THREADS                4096 /**< Maximum number of threads. */
#define MAX_FILE_PATH_LEN           255 /**< Maximum file path length.  */


/*** Errors ***/
#define E_ATTK_SYSTEM                -1 /**< Error return for file functions
                                         *   indicating a system error occurred
                                         */
#define E_ATTK_STOPPED               -2 /**< Error return for check_attack
                                         *   function, incidates the attack is
                                         *   over and the callback has been
                                         *   called.
                                         */
#define E_ATTK_RECORD_INVALID        -3 /**< Error returned when attack_check
                                         *   function incidates the record was
                                         *   invalid and was not checked.
                                         */
#define E_ATTK_RECORD_NO_MATCH       -4 /**< Error returned when attack_check
                                         *   function indicates the record was
                                         *   not a match.
                                         */
#define E_ATTK_RECORD_SIZE_INVALID   -5 /**< Error returned when record size is
                                         *   invalid.
                                         */
#define E_ATTK_FILE_INVALID          -6 /**< Error returned when an input or
                                         *   output file is invalid.
                                         */


/** Attack error state enum.
 *  Indicates the where the error occured.
 */
typedef enum {
    E_STATE_INPUT_FILE = 1, /**< Error occured in input file.  */
    E_STATE_OUTPUT_FILE,    /**< Error occured in output file. */
} error_state;


/** Attack state enum.
 *  Indicates the state of the attack.
 */
typedef enum {
    ATTACK_STATE_ACTIVE = 1, /**< Attack active state.   */
    ATTACK_STATE_STOPPING,   /**< Attack stopping state. */
    ATTACK_STATE_STOPPED     /**< Attack stopped state.  */
} attack_state;


/** Attack status structure.
 *  Stores information about the current status of the attack.
 */
typedef struct ATTACK_STATUS {
    uint64_t records_tested;    /**< Number of records tested. */
    uint64_t total_records;     /**< Total number of records.  */
    char *result;               /**< The result.               */
    size_t result_size;         /**< The length of the result. */
} attack_status;

/** File attack structure.
 *  Structure that holds the file data for a threaded attack.
 */
struct FILE_ST {
    char file_path[MAX_FILE_PATH_LEN + 1];  /**< File path.                   */
    uint16_t record_size;                   /**< Record size.                 */
    int records_per_block;                  /**< Words to process per thread. */
    uint64_t total_records;                 /**< Total number of records.     */

    /* The file interface */
    int (*open_file)(struct FILE_ST *file); /**< Function to open the file.   */
    ssize_t (*next_block)(struct FILE_ST *file, char **buf,
                          size_t buf_size); /**< Function to read the next
                                             *   block.  Returns number of bytes
                                             *   read, or 0 for EOF.
                                             */
    int (*free_block)(struct FILE_ST *file, char *buf,
                       size_t buf_len);     /**< Function to free a block.    */
    int (*close_file)(struct FILE_ST *file);/**< Function to close the file.  */

    void *file_data;                        /**< Pointer to extra file data.  */

    pthread_mutex_t mut;                    /**< Thread mutex for file data.  */
};
/** File attack structure.
 *  Structure that holds the file data for a threaded attack.
 */
typedef struct FILE_ST file_st;

/** Attack structure.
 *  Structure that holds the running data for a threaded attack.
 */
struct ATTACK_ST {
    int threads;            /**< Number of client threads.                    */
    pthread_t main;         /**< Main thread.                                 */

    int (*attack_check)(char *record, size_t record_size,
                        char *ret_record, size_t return_size,
                        void *attack_data);   /**< The attack function to call
                                               *   for each record.
                                               */
    int (*callback)(struct ATTACK_ST *fargs); /**< Callback function, called
                                               *   upon completion.
                                               */

    file_st *file_in;       /**< Pointer to input file structure.             */
    file_st *file_out;      /**< Pointer to output file structure.            */
    void *attack_data;      /**< Pointer to attack data.                      */
    void *callback_data;    /**< Pointer to callback data.                    */

    /* Private */
    attack_status _s;       /**< Private status data.                         */

    int error;              /**< Error value, if any.                         */
    error_state e_state;    /**< Error state, where the error occured.        */
    attack_state state;     /**< Current attack state.                        */
    pthread_mutex_t mut;    /**< Thread mutex for all attack data.            */
};
/** Attack structure.
 *  Structure that holds the running data for a threaded attack.
 */
typedef struct ATTACK_ST attack_st;


int attack_st_init(attack_st *attk_st, file_st *file_in, file_st *file_out,
                   int threads, int (*attack_check)(char *record,
                                                    size_t record_size,
                                                    char *ret_record,
                                                    size_t return_size,
                                                    void *attack_data),
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, void *attack_data);
int attack_st_destroy(attack_st *attack_st);
int start_attack(attack_st *attk_st);
int start_attack_c(attack_st *attk_st,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data);
int check_attack(attack_st *attk_st, attack_status *status);
void stop_attack(attack_st *attk_st);

/** @} */

#endif      /* LIBATTKTHREADING_H */

