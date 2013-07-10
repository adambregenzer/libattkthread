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

#include "read_file.h"
#include "../config.h"

/** @defgroup read_file read_file
 *
 *  Process a file as a set of records.
 *
 *  Read file implements the file interface for libattkthread.  Opens a file
 *  and reads through it, processing the file in chunks of records.
 */

/** Initializes a read file structure.
 *  Clears a new read file structure, copies the file path, sets the record
 *  size, and sets up its thread mutex.
 *
 *  @param[in] file                 The file structure.
 *  @param[in] records_per_block    The number of records per block.
 *  @param[in] file_path            The file's path.
 *  @param[in] file_description     The file's description.
 *  @param[in] file_order           The file's order number.
 *  @param[in] skip_records         Number of records to skip past.
 *  @param[in] count_records        Total number of records to calculate, 0 for
 *                                  all records.
 */
void read_file_init(file_st *file, int records_per_block, char *file_path,
                    char *file_description, uint64_t skip_records,
                    uint64_t count_records) {
    size_t file_path_len = MAX_FILE_PATH_LEN < strlen(file_path) ?
                           MAX_FILE_PATH_LEN : strlen(file_path);
    read_file_data_st *read_file_st;
    int fp;
    read_file_header_st header;

    #ifdef DEBUG
    printf("read_file_init: START %p|%i|%s|%s|%i|%i|%i\n", file,
           records_per_block, file_path, file_description, skip_records,
           count_records);
    #endif

    /* Clear the structure */
    memset(file, 0, sizeof(file_st));

    /* Set defaults */
    memcpy(file->file_path, file_path, file_path_len);
    file->records_per_block = records_per_block;

    /* Initialize pthread objects */
    pthread_mutex_init(&(file->mut), NULL);

    /* Create read_file_data_st */
    read_file_st = malloc(sizeof(read_file_data_st));
    memset(read_file_st, 0, sizeof(read_file_data_st));
    file->file_data = read_file_st;
    memcpy(read_file_st->description, file_description, 255);
    read_file_st->skip_records = skip_records;
    read_file_st->max_records = count_records;

    /* Open the file so we can get the record size */
    fp = open(file->file_path, O_RDONLY|O_LARGEFILE);
    if (fp < 0) {
        #ifdef DEBUG
        printf("read_file_init: Can not open file (%s)\n", file->file_path);
        #endif
    }

    /* Read the header */
    read(fp, &header.magic, sizeof(header.magic));
    read(fp, &header.description, sizeof(header.description));
    read(fp, &header.file_order, sizeof(header.file_order));
    read(fp, &header.record_size, sizeof(header.record_size));
    header.record_size = ntohs(header.record_size);
    header.file_order = ntohl(header.file_order);

    /* Save the file order and record size */
    read_file_st->file_order = header.file_order;
    file->record_size = header.record_size;

    /* Close the file */
    close(fp);

    /* Setup class methods */
    file->open_file = read_open_file;
    file->next_block = read_next_block;
    file->free_block = read_free_block;
    file->close_file = read_close_file;
}

/** Destroys a read file structure.
 *  Clears a read file structure and destroys its thread mutex.  Also clears all
 *  private data.
 *
 *  @param[in] file The file to destroy.
 */
void read_file_destroy(file_st *file) {
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
int read_open_file(file_st *file) {
    read_file_data_st *read_file_st = file->file_data;
    struct stat file_stat;
    int fp;
    read_file_header_st header;
    int retval;

    #ifdef DEBUG
    printf("read_open_file: START (%s)\n", file->file_path);
    #endif

    /* Open the file */
    fp = open(file->file_path, O_RDONLY|O_LARGEFILE);
    if (fp < 0) {
        #ifdef DEBUG
        printf("read_open_file: Can not open file (%s)\n", file->file_path);
        #endif
        /* Can not open file */
        return E_ATTK_SYSTEM;
    }

    /* Read the header */
    read(fp, &header.magic, sizeof(header.magic));
    read(fp, &header.description, sizeof(header.description));
    read(fp, &header.file_order, sizeof(header.file_order));
    read(fp, &header.record_size, sizeof(header.record_size));
    read(fp, &header.reserved, sizeof(header.reserved));
    header.magic = ntohl(header.magic);
    header.file_order = ntohl(header.file_order);
    header.record_size = ntohs(header.record_size);
    file->record_size = header.record_size;

    if (header.magic != READ_FILE_MAGIC) {
        #ifdef DEBUG
        printf("read_open_file: Bad file magic.\n");
        #endif
        return E_ATTK_FILE_INVALID;
    }
    if (header.file_order != read_file_st->file_order) {
        #ifdef DEBUG
        printf("read_open_file: Bad file order. - %i != %i\n",
               header.file_order, read_file_st->file_order);
        #endif
        return E_ATTK_FILE_INVALID;
    }
    if (strlen(header.description) != strlen(read_file_st->description)) {
        #ifdef DEBUG
        printf("read_open_file: Bad file description size.\n");
        #endif
        return E_ATTK_FILE_INVALID;
    }
    if (memcmp(header.description, read_file_st->description,
               strlen(header.description)) != 0) {
        #ifdef DEBUG
        printf("read_open_file: Bad file description.\n");
        #endif
        return E_ATTK_FILE_INVALID;
    }

    /* Set the total number of records to read */
    if (read_file_st->max_records == 0) {
        /* Get the file size */
        retval = fstat(fp, &file_stat);
        if (retval == -1){
            #ifdef DEBUG
            printf("read_open_file: Can not get file size.\n");
            #endif
            return E_ATTK_SYSTEM;
        }
        file->total_records = file_stat.st_size / file->record_size;
    } else {
        file->total_records = read_file_st->max_records;
    }

    /* Skip records, if needed */
    if (read_file_st->skip_records > 0) {
        lseek64(read_file_st->fp, file->record_size*read_file_st->skip_records,
                SEEK_CUR);
    }

    /* Save the file pointer */
    read_file_st->fp = fp;

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
ssize_t read_next_block(file_st *file, char **buf, size_t buf_size) {
    read_file_data_st *read_file_st = file->file_data;
    char *buffer;

    #ifdef DEBUG
    printf("read_next_block: START\n");
    #endif

    /* Sanity check */
    assert(read_file_st->fp > 0);

    /* Calculate buffer size */
    if (buf_size == 0) {
        if (read_file_st->max_records > 0 && read_file_st->max_records <
            (file->records_per_block + read_file_st->current_record)) {
            buf_size = file->record_size *
                (read_file_st->max_records - read_file_st->current_record);
        } else {
            buf_size = file->record_size * file->records_per_block;
        }

        /* Allocate buffer */
        buffer = malloc(buf_size);
        *buf = buffer;
    } else {
        buf_size = (buf_size / file->record_size) * file->record_size;
        buffer = *buf;
    }

    /* Read in record block */
    buf_size = read(read_file_st->fp, buffer, buf_size);

    /* Update number of records read */
    read_file_st->current_record += buf_size / file->record_size;

    return buf_size;
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
int read_free_block(file_st *file, char *buf, size_t buf_len) {
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
int read_close_file(file_st *file) {
    read_file_data_st *read_file_st = file->file_data;

    /* Sanity check */
    assert(read_file_st->fp > 0);

    /* Close the file */
    return close(read_file_st->fp);
}

