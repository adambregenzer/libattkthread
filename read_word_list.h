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

#ifndef READ_WORD_LIST_H
#define READ_WORD_LIST_H

#include <stdint.h>

#include "libattkthread.h"

/** @addtogroup read_word_list
 *  @{
 */

/** Read file structure.
 *  Private data used by read_word_list.
 */
typedef struct READ_WL_DATA_ST {
    FILE *fp;   /**< File pointer. */
} read_wl_data_st;

void read_word_list_init(file_st *file, char *file_path, int records_per_block,
                         size_t record_size);
void read_word_list_destroy(file_st *file);
int read_wl_open_file(file_st *file);
ssize_t read_wl_next_block(file_st *file, char **buf, size_t buf_size);
int read_wl_free_block(file_st *file, char *buf, size_t buf_len);
int read_wl_close_file(file_st *file);

/** @} */

#endif /* READ_WORD_LIST_H */

