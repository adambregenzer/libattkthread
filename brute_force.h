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

#ifndef BRUTE_FORCE_H
#define BRUTE_FORCE_H

#include <stdint.h>

#include "libattkthread.h"

/** @addtogroup brute_force
 *  @{
 */

/** Brute force file structure.
 *  Private data used by brute_force.
 */
typedef struct BRUTE_FORCE_DATA_ST {
    char *start;            /**< Start string. */
    char *end;              /**< End string. */
    char *alphabet;         /**< Alphabet string to use. */
    char *last;             /**< Last record generated. */
} brute_force_data_st;

int brute_force_init(file_st *file, int records_per_block, char *start,
                     char *end, char *alphabet);
void brute_force_destroy(file_st *file);
int bf_open_file(file_st *file);
ssize_t bf_next_block(file_st *file, char **buf, size_t buf_size);
int bf_free_block(file_st *file, char *buf, size_t buf_len);
int bf_close_file(file_st *file);

/** @} */

#endif /* BRUTE_FORCE_H */

