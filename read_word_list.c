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
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "read_word_list.h"

#define BUFFSIZE    256

/** @defgroup read_word_list read_word_list
 *
 *  Process a file as a list of words, one per line.
 *
 *  Read word list implements the file interface for libattkthread.  Opens a
 *  file and reads through it, processing the file as a list of words, one per
 *  line.
 */


/** Private method that finds the longest line in a file.
 *  Private method that finds the longest line in a file, does not count the
 *  newline character.  Only supports UNIX style end of line character - 0x0A.
 *
 *  @param[in] file_path    The file's path.
 *
 *  @return                 Returns the length of the longest line, otherwise an
 *                          error code.
 */
size_t find_max_line_len(char *file_path) {
    FILE *fp = NULL;        /* File pointer         */
    char buffer[BUFFSIZE];  /* Read buffer          */
    size_t curr_len;        /* Current line length  */
    size_t max_len;         /* Longest length found */

    /* Open the file */
    fp = fopen(file_path, "r");
    if (fp == NULL) {
        return E_ATTK_SYSTEM;
    }

    /* Find the longest line */
    max_len = curr_len = 0;
    while (feof(fp) == 0) {
        memset(buffer, 0, BUFFSIZE);
        fgets(buffer, BUFFSIZE, fp);
        curr_len += strlen(buffer);
        if (*(buffer + strlen(buffer) - 1) == '\n') {
            if (curr_len > max_len) {
                max_len = curr_len - 1;
            }
            curr_len = 0;
        }
    }
    if (*(buffer + strlen(buffer) - 1) == '\n') {
        if (curr_len > max_len) {
            max_len = curr_len - 1;
        }
        curr_len = 0;
    } else {
        if (curr_len > max_len) {
            max_len = curr_len;
        }
    }

    /* Close the file */
    fclose(fp);

    return max_len;
}


/** Initializes a read word list structure.
 *  Clears a new read word list structure, copies the file path, sets the record
 *  size, and sets up its thread mutex.
 *
 *  @param[in] file                 The file structure.
 *  @param[in] records_per_block    The number of records per block.
 *  @param[in] file_path            The file's path.
 */
void read_word_list_init(file_st *file, char *file_path, int records_per_block,
                         size_t record_size) {
    size_t file_path_len = MAX_FILE_PATH_LEN < strlen(file_path) ?
                           MAX_FILE_PATH_LEN : strlen(file_path);
    read_wl_data_st *read_wl_st;

    /* Clear the structure */
    memset(file, 0, sizeof(file_st));

    /* Set defaults */
    memcpy(file->file_path, file_path, file_path_len);
    file->records_per_block = records_per_block;
    file->record_size = record_size;

    /* Initialize pthread objects */
    pthread_mutex_init(&(file->mut), NULL);

    /* Create read_file_data_st */
    read_wl_st = malloc(sizeof(read_wl_data_st));
    memset(read_wl_st, 0, sizeof(read_wl_data_st));
    file->file_data = read_wl_st;

    /* Setup class methods */
    file->open_file = read_wl_open_file;
    file->next_block = read_wl_next_block;
    file->free_block = read_wl_free_block;
    file->close_file = read_wl_close_file;
}

/** Destroys a read word list structure.
 *  Clears a read word list structure and destroys its thread mutex.  Also
 *  clears all private data.
 *
 *  @param[in] file The file to destroy.
 */
void read_word_list_destroy(file_st *file) {
    /* Destroy pthread objects */
    pthread_mutex_destroy(&(file->mut));

    /* Destroy read_file_data_st */
    free(file->file_data);
}

/** Open the file.
 *  Opens the file and starts processing it.
 *
 *  @param[in] file The file structure.
 *
 *  @return         Returns 0 on success, otherwise an error code.
 */
int read_wl_open_file(file_st *file) {
    read_wl_data_st *read_wl_st = file->file_data;
    FILE *fp;
    int retval;

    /* Set the total number of records to read */
    if (file->record_size == 0) {
        retval = find_max_line_len(file->file_path);
        if (retval == E_ATTK_SYSTEM) {
            /* Can't open it */
            return E_ATTK_SYSTEM;
        } else {
            file->record_size = retval + 1;
        }
    }

    /* Open the file */
    fp = fopen(file->file_path, "r");
    if (fp == NULL) {
        /* Can not open file */
        return E_ATTK_SYSTEM;
    }

    /* Save the file pointer */
    read_wl_st->fp = fp;

    return 0;
}

/** Read in a block and return it.
 *  Reads in a block of data and allocates it into a buffer.
 *
 *  @param[in]  file        The file structure.
 *  @param[out] buf         The block to return.
 *  @param[in]  buf_size    The size of the block, 0 if block is not allocated.
 *
 *  @return                 Returns the number of bytes read, otherwise an error
 *                          code.
 */
ssize_t read_wl_next_block(file_st *file, char **buf, size_t buf_size) {
    read_wl_data_st *read_wl_st = file->file_data;
    char *buffer;
    char *read_buf;
    char *curr_buf_p;

    /* Sanity check */
    assert(read_wl_st->fp != NULL);

    if (buf_size == 0) {
        /* Calculate buffer size */
        buf_size = file->record_size * file->records_per_block;

        /* Allocate buffer */
        buffer = malloc(buf_size);
        *buf = buffer;
    } else {
        buf_size = (buf_size / file->record_size) * file->record_size;
        buffer = *buf;
    }

    /* Allocate read buffer */
    read_buf = malloc(file->record_size + 1);

    /* Read in words */
    curr_buf_p = buffer;
    while (curr_buf_p < (buffer + buf_size)) {
        /* End of File */
        if (feof(read_wl_st->fp)) {
            break;
        }

        /* Read in next line and add it to the return buffer */
        memset(read_buf, 0, file->record_size + 1);
        fgets(read_buf, file->record_size + 1, read_wl_st->fp);
        if (read_buf[strlen(read_buf) - 1] != '\n' && !feof(read_wl_st->fp)) {
            return E_ATTK_RECORD_SIZE_INVALID;
        }
        read_buf[strlen(read_buf) - 1] = '\0';
        if (strlen(read_buf) > 0) {
            memcpy(curr_buf_p, read_buf, file->record_size);
            curr_buf_p += file->record_size;
        }
    }

    /* Free read buffer */
    free(read_buf);

    return curr_buf_p - buffer;
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
int read_wl_free_block(file_st *file, char *buf, size_t buf_len) {
    /* Free the buffer */
    free(buf);

    return 0;
}

/** Close the file.
 *  Closes the file when done.
 *
 *  @param[in]  file    The file structure.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int read_wl_close_file(file_st *file) {
    read_wl_data_st *read_wl_st = file->file_data;

    /* Sanity check */
    assert(read_wl_st->fp != NULL);

    /* Close the file */
    return fclose(read_wl_st->fp);
}

