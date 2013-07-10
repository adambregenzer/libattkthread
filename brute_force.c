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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "brute_force.h"

/** @defgroup brute_force brute_force
 *
 *  Generate a series of records based on the supplied alphabet.
 *
 *  Brute force implements the file interface for libattkthread.
 *  It generates a series of records starting with the start
 *  buffer, stopping when it reaches the end buffer, and using
 *  the alphabet string as the sequence of characters to
 *  process.
 */

inline char *char_index(char *haystack, size_t hay_size, char *needle) {
    return (char *)memchr(haystack, (int)*needle, hay_size);
}
inline char *alp_index(file_st *file, char *needle) {
    brute_force_data_st *bf_st = file->file_data;
    return (char *)memchr(bf_st->alphabet, (int)*needle,
                          strlen(bf_st->alphabet));
}

/** Initializes a read file structure.
 *  Clears a new read file structure, copies the file path, sets the record
 *  size, and sets up its thread mutex.
 *
 *  @param[in] file                 The file structure.
 *  @param[in] records_per_block    The number of records per block.
 *  @param[in] start                Start string.
 *  @param[in] end                  End string.
 *  @param[in] alphabet             Alphabet string to use.
 */
int brute_force_init(file_st *file, int records_per_block, char *start,
                     char *end, char *alphabet) {
    brute_force_data_st *bf_st;
    size_t start_len;
    size_t end_len;
    size_t alp_len;
    int i;

    start_len = strlen(start);
    end_len = strlen(end);
    alp_len = strlen(alphabet);

    /* Start can not be longer than end */
    if (start_len > end_len) {
        errno = EINVAL;
        return E_ATTK_SYSTEM;
    }

    /* Every character in start must be in the alphabet */
    for (i = 0; i < start_len; i++) {
        if (char_index(alphabet, alp_len, start + i) == NULL) {
            errno = EINVAL;
            return E_ATTK_SYSTEM;
        }
    }

    /* Every character in end must be in the alphabet */
    for (i = 0; i < end_len; i++) {
        if (char_index(alphabet, alp_len, end + i) == NULL) {
            errno = EINVAL;
            return E_ATTK_SYSTEM;
        }
    }

    /* If they are the same size, start can not be greater than end */
    if (start_len == end_len) {
        for (i = 0; i < start_len; i++) {
            if (char_index(alphabet, alp_len, start + i)
                   > char_index(alphabet, alp_len, end + i)) {
                errno = EINVAL;
                return E_ATTK_SYSTEM;
            }
            if (char_index(alphabet, alp_len, start + i)
                < char_index(alphabet, alp_len, end + i)) {
                break;
            }
        }
    }

    /* Clear the structure */
    memset(file, 0, sizeof(file_st));

    /* Set defaults */
    file->record_size = strlen(end) + 1;
    file->records_per_block = records_per_block;

    /* Initialize pthread objects */
    pthread_mutex_init(&(file->mut), NULL);

    /* Create brute_force_data_st */
    bf_st = malloc(sizeof(brute_force_data_st));
    file->file_data = bf_st;

    /* Create buffers */
    bf_st->start = malloc(strlen(start) + 1);
    bf_st->end = malloc(strlen(end) + 1);
    bf_st->alphabet = malloc(strlen(alphabet) + 1);
    bf_st->last = malloc(strlen(end) + 1);
    memset(bf_st->start, 0, strlen(start) + 1);
    memset(bf_st->end, 0, strlen(end) + 1);
    memset(bf_st->alphabet, 0, strlen(alphabet) + 1);
    memset(bf_st->last, 0, strlen(end) + 1);

    /* Fill buffers */
    memcpy(bf_st->start, start, strlen(start));
    memcpy(bf_st->end, end, strlen(end));
    memcpy(bf_st->alphabet, alphabet, strlen(alphabet));

    /* Setup class methods */
    file->open_file = bf_open_file;
    file->next_block = bf_next_block;
    file->free_block = bf_free_block;
    file->close_file = bf_close_file;

    return 0;
}

/** Destroys a brute force structure.
 *  Clears a brute force structure and destroys its thread mutex.  Also clears
 *  all private data.
 *
 *  @param[in] file The file to destroy.
 */
void brute_force_destroy(file_st *file) {
    brute_force_data_st *bf_st = file->file_data;

    /* Destroy pthread objects */
    pthread_mutex_destroy(&(file->mut));

    /* Destroy brute_force_data_st */
    free(bf_st->start);
    free(bf_st->end);
    free(bf_st->alphabet);
    free(bf_st->last);
    free(bf_st);
}

/** Start the generator.
 *  Calculates the number of words that will be generated.
 *
 *  @param[in] file The file structure.
 *
 *  @return         Returns 0 on success, otherwise an error code.
 */
int bf_open_file(file_st *file) {
    brute_force_data_st *bf_st = file->file_data;
    char *curr_p;
    char *start_end_p;
    char *end_end_p;
    char *alp_end_p;
    size_t start_len;
    size_t end_len;
    size_t alp_len;
    unsigned long temp;
    int i, j;

    /* Calculate string lengths */
    start_len = strlen(bf_st->start);
    end_len = strlen(bf_st->end);
    alp_len = strlen(bf_st->alphabet);

    /* Calculate pointers to the ends of the strings */
    start_end_p = bf_st->start + start_len - 1;
    end_end_p = bf_st->end + end_len - 1;
    alp_end_p = bf_st->alphabet + alp_len - 1;

    /* Calculate the total number of records */
    file->total_records = 1;
    /* Calculate number of records to finish start string */
    curr_p = start_end_p;
    while (curr_p >= bf_st->start) {
        temp = alp_end_p - alp_index(file, curr_p);
        for (i = 0; i < start_end_p - curr_p; i++) {
            temp *= alp_len;
        }
        file->total_records += temp;
        curr_p--;
    }
    /* Calculate number of records to reach end's length */
    for (i = 0; i < (end_len - start_len); i++) {
      temp = alp_len;
      for (j = 0; j < (start_len + i); j++) {
        temp *= alp_len;
      }
      file->total_records += temp;
    }
    /* Remove possibilities that will not be generated */
    curr_p = end_end_p;
    while (curr_p >= bf_st->end) {
      temp = alp_end_p - alp_index(file, curr_p);
      for (i = 0; i < (end_end_p - curr_p); i++) {
        temp *= alp_len;
      }
      file->total_records -= temp;
      curr_p--;
    }

    return 0;
}

/** Read in a block and return it.
 *  Generates the next block of records and allocates it into a buffer.
 *
 *  @param[in]  file        The file structure.
 *  @param[out] buf         The block to return.
 *  @param[in]  buf_size    The size of the block, 0 if block is not allocated.
 *
 *  @return                 Returns the number of bytes, otherwise an error code.
 */
ssize_t bf_next_block(file_st *file, char **buf, size_t buf_size) {
    brute_force_data_st *bf_st = file->file_data;
    char *buffer;
    char *buf_p;
    char *start_end_p;
    char *end_end_p;
    char *alp_end_p;
    char *last_end_p;
    char *curr_p;
    size_t start_len;
    size_t end_len;
    size_t alp_len;

    /* Calculate string lengths */
    start_len = strlen(bf_st->start);
    end_len = strlen(bf_st->end);
    alp_len = strlen(bf_st->alphabet);

    /* Calculate pointers to the ends of the strings */
    start_end_p = bf_st->start + start_len - 1;
    end_end_p = bf_st->end + end_len - 1;
    alp_end_p = bf_st->alphabet + alp_len - 1;

    /* Calculate buffer size */
    if (buf_size == 0) {
        /* Calculate buffer size */
        buf_size = file->record_size * file->records_per_block;

        /* Allocate buffer */
        buffer = malloc(buf_size);
        memset(buffer, 0, buf_size);
        *buf = buffer;
    } else {
        buf_size = (buf_size / file->record_size) * file->record_size;
        buffer = *buf;
    }
    buf_p = buffer;

    /* First run? */
    if (strlen(bf_st->last) == 0) {
        memcpy(bf_st->last, bf_st->start, strlen(bf_st->start));
        memcpy(buffer, bf_st->last, strlen(bf_st->last));
        buf_p += file->record_size;
    }

    /* Generate more records */
    last_end_p = bf_st->last + strlen(bf_st->last) - 1;
    while (buf_p < (buffer + buf_size)) {
        if (memcmp(bf_st->last, bf_st->end, end_len) == 0) {
            /* All records generated */
            break;
        }

        /* Find the first char to increase */
        curr_p = last_end_p;
        while (memcmp(curr_p, alp_end_p, 1) == 0) {
            if (curr_p < bf_st->last) {
                break;
            }
            curr_p--;
        }
        if (curr_p < bf_st->last) {
            /* We need to make the string longer */
            if (strlen(bf_st->last) < end_len) {
                memset(bf_st->last, (int)*bf_st->alphabet,
                       strlen(bf_st->last) + 1);
                last_end_p++;
            } else {
                /* All records generated */
                break;
            }
        } else {
            /* Increase char to next in alphabet */
            memcpy(curr_p, alp_index(file, curr_p) + 1, 1);
            curr_p++;

            /* Reset any following characters */
            while (curr_p <= last_end_p) {
                memcpy(curr_p, bf_st->alphabet, 1);
                curr_p++;
            }
        }

        /* Add this word to the buffer */
        memcpy(buf_p, bf_st->last, strlen(bf_st->last));
        buf_p += file->record_size;
    }

    return buf_p - buffer;
}

/** Free a block.
 *  Frees a block that was previously read.
 *
 *  @param[in]  file    The file structure.
 *  @param[in]  buf     The block to free.
 *  @param[in]  buf_len The size of the block.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int bf_free_block(file_st *file, char *buf, size_t buf_len) {
    /* Free the buffer */
    free(buf);

    return 0;
}

/** Close the file.
 *  Does nothing for brute force.
 *
 *  @param[in]  file    The file structure.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int bf_close_file(file_st *file) {
    /* Nothing to do */
    return 0;
}

