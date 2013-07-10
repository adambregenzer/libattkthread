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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "read_file.h"
#include "write_file.h"

/** @defgroup write_file write_file
 *
 *  Write a set of records to a file.
 *
 *  Write file implements the file interface for libattkthread.  Opens a file
 *  and write blocks of records to it.
 */

/** Initializes a write file structure.
 *  Clears a new write file structure, copies the file path, sets the record
 *  size, and sets up its thread mutex.
 *
 *  @param[in] file                 The file structure.
 *  @param[in] file_path            The file's path.
 *  @param[in] file_description     The file's description.
 *  @param[in] file_order           The file's order number.
 *  @param[in] record_size          The size of each record.
 */
void write_file_init(file_st *file, char *file_path, char *file_description,
                     uint32_t file_order, uint16_t record_size) {
    size_t file_path_len = MAX_FILE_PATH_LEN < strlen(file_path) ?
                           MAX_FILE_PATH_LEN : strlen(file_path);
    write_file_data_st *write_file_st;

    /* Clear the structure */
    memset(file, 0, sizeof(file_st));

    /* Set defaults */
    memcpy(file->file_path, file_path, file_path_len);
    file->record_size = record_size;

    /* Initialize pthread objects */
    pthread_mutex_init(&(file->mut), NULL);

    /* Create write_file_data_st */
    write_file_st = malloc(sizeof(write_file_data_st));
    memset(write_file_st, 0, sizeof(write_file_data_st));
    file->file_data = write_file_st;
    memcpy(write_file_st->description, file_description, strlen(file_description));
    write_file_st->file_order = file_order;

    /* Setup class methods */
    file->open_file = write_open_file;
    file->next_block = write_next_block;
    file->free_block = write_free_block;
    file->close_file = write_close_file;
}

/** Destroys a write file structure.
 *  Clears a write file structure and destroys its thread mutex.  Also clears
 *  all private data.
 *
 *  @param[in] file The file to destroy.
 */
void write_file_destroy(file_st *file) {
    /* Destroy pthread objects */
    pthread_mutex_destroy(&(file->mut));

    /* Destroy write_file_data_st */
    free(file->file_data);
}

/** Open the file.
 *  Opens the file and starts processing it.
 *
 *  @param[in] file The file structure.
 *
 *  @return         Returns 0 on success, otherwise an error code.
 */
int write_open_file(file_st *file) {
    write_file_data_st *write_file_st = file->file_data;
    struct stat file_stat;
    int fp;
    read_file_header_st header;
    int retval;

    memset(&header, 0, sizeof(read_file_header_st));

    /* Check if the file already exists */
    retval = stat(file->file_path, &file_stat);
    if (errno == ENOENT) {
        errno = 0;
        /* File does not exist, open the file */
        fp = open(file->file_path, O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE,
                  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (fp < 0) {
            /* Can not open file */
            return E_ATTK_SYSTEM;
        }

        /* Write the header */
        header.magic = htonl(READ_FILE_MAGIC);
        memcpy(header.description, write_file_st->description, 255);
        header.file_order = htonl(write_file_st->file_order);
        header.record_size = htons(file->record_size);
        write(fp, &header.magic, sizeof(header.magic));
        write(fp, &header.description, sizeof(header.description));
        write(fp, &header.file_order, sizeof(header.file_order));
        write(fp, &header.record_size, sizeof(header.record_size));
        write(fp, &header.reserved, sizeof(header.reserved));
    } else {
        /* File already exists, open the file */
        fp = open(file->file_path, O_RDWR|O_LARGEFILE);
        if (fp < 0) {
            /* Can not open file */
            return E_ATTK_SYSTEM;
        }

        /* Check the header */
        read(fp, &header.magic, sizeof(header.magic));
        read(fp, &header.description, sizeof(header.description));
        read(fp, &header.file_order, sizeof(header.file_order));
        read(fp, &header.record_size, sizeof(header.record_size));
        read(fp, &header.reserved, sizeof(header.reserved));
        header.magic = ntohl(header.magic);
        header.file_order = ntohl(header.file_order);
        header.record_size = ntohs(header.record_size);

        if (file->record_size <= header.record_size) {
            file->record_size = header.record_size;
        }

        if (header.magic != READ_FILE_MAGIC) {
            return E_ATTK_FILE_INVALID;
        }
        if (header.file_order != write_file_st->file_order) {
            return E_ATTK_FILE_INVALID;
        }
        if (header.record_size < file->record_size) {
            return E_ATTK_RECORD_SIZE_INVALID;
        }
        if (strlen(header.description) != strlen(write_file_st->description)) {
            return E_ATTK_FILE_INVALID;
        }
        if (memcmp(header.description, write_file_st->description,
                   strlen(header.description)) != 0) {
            return E_ATTK_FILE_INVALID;
        }

        /* Seek to the end of the file */
        lseek(fp, 0, SEEK_END);
    }

    /* Save the file pointer */
    write_file_st->fp = fp;
    return 0;
}

/** Write a block to the file.
 *  Writes out the passed block of data.
 *
 *  @param[in]  file        The file structure.
 *  @param[out] buf         The block to write.
 *  @param[in]  buf_size    The size of the block.
 *
 *  @return                 Returns the number of bytes written, otherwise an
 *                          error code.
 */
ssize_t write_next_block(file_st *file, char **buf, size_t buf_size) {
    write_file_data_st *write_file_st = file->file_data;
    int retval;
    char *buf_p = *buf;
    size_t written = 0;
    size_t counter = 0;

    /* Sanity check */
    assert(write_file_st->fp > 0);

    /* Write record block */
    while (written < buf_size) {
        /* Write out the buffer */
        retval = write(write_file_st->fp, buf_p, buf_size - written);
        if (retval >= 0) {
            written += retval;
            buf_p += retval;

            /* Catch a potential infinite loop where write always returns 0,
               we will not call write more than buf_size times */
            counter++;
            if (counter > buf_size) {
                return E_ATTK_SYSTEM;
            }
        } else {
            return E_ATTK_SYSTEM;
        }
    }

    return written;
}

/** Placeholder for free_block, always returns an error.
 *  Always returns an error!
 *
 *  @param[in]  file    The file structure.
 *  @param[in]  buf     The block to free.
 *  @param[in]  buf_len The size of the block.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int write_free_block(file_st *file, char *buf, size_t buf_len) {
    /* This is an error! */
    assert(-1);

    return -1;
}

/** Close the file.
 *  Closes the file when done.
 *
 *  @param[in]  file    The file structure.
 *
 *  @return             Returns 0 on success, otherwise an error code.
 */
int write_close_file(file_st *file) {
    write_file_data_st *write_file_st = file->file_data;

    /* Close the file */
    if (write_file_st->fp > 0) {
        return close(write_file_st->fp);
    }

    return 0;
}

