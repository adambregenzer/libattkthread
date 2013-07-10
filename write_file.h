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

#ifndef WRITE_FILE_H
#define WRITE_FILE_H

#include <stdint.h>

#include "libattkthread.h"

/** @addtogroup write_file
 *  @{
 */

/** Write file structure.
 *  Private data used by write_file.
 */
typedef struct WRITE_FILE_DATA_ST {
    int fp;                     /**< File pointer.                      */
    char description[256];      /**< File's description.                */
    uint32_t file_order;        /**< File's order.                      */
} write_file_data_st;

void write_file_init(file_st *file, char *file_path, char *file_description,
                     uint32_t file_order, uint16_t record_size);
void write_file_destroy(file_st *file);
int write_open_file(file_st *file);
ssize_t write_next_block(file_st *file, char **buf, size_t buf_size);
int write_free_block(file_st *file, char *buf, size_t buf_len);
int write_close_file(file_st *file);

/** @} */

#endif /* WRITE_FILE_H */

