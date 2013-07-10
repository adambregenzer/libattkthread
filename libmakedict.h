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

#ifndef LIBMAKEDICT_H
#define LIBMAKEDICT_H

#include <stdint.h>

#include "libattkthread.h"

int make_dict_init(attack_st *attk_st, char *word_file_path,
                   char *dict_file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   uint32_t file_order, size_t rec_size);
int make_dict_destroy(attack_st *attack_st);

#endif      /* LIBMAKEDICT_H */

