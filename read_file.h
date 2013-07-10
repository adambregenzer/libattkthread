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

#ifndef READ_FILE_H
#define READ_FILE_H

#include <stdint.h>

#include "libattkthread.h"

/** @addtogroup read_file
 *  @{
 */

#define READ_FILE_MAGIC 0x11BA77AC

/** File header structure.
 *  Data at the beginning of a file.
 */
typedef struct READ_FILE_HEADER_ST {
    uint32_t magic;
    char description[256];
    uint32_t file_order;
    uint16_t record_size;
    uint16_t reserved;
} __attribute__ ((packed)) read_file_header_st;

/** Read file structure.
 *  Private data used by read_file.
 */
typedef struct READ_FILE_DATA_ST {
    int fp;                     /**< File pointer.                      */
    char description[256];      /**< File's description.                */
    uint32_t file_order;        /**< File's order.                      */
    uint64_t skip_records;      /**< Number of records to skip.         */
    uint64_t max_records;       /**< Maximum number of records to read. */
    uint64_t current_record;    /**< Current record count.              */
} read_file_data_st;

void read_file_init(file_st *file, int records_per_block, char *file_path,
                    char *file_description, uint64_t skip_records,
                    uint64_t count_records);
void read_file_destroy(file_st *file);
int read_open_file(file_st *file);
ssize_t read_next_block(file_st *file, char **buf, size_t buf_size);
int read_free_block(file_st *file, char *buf, size_t buf_len);
int read_close_file(file_st *file);

/** @} */

#endif /* READ_FILE_H */

