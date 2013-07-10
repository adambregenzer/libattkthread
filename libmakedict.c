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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "libattkthread.h"
#include "read_word_list.h"
#include "write_file.h"

#define WORDS_PER_THREAD    4096

int do_make_dict(char *word, size_t word_size, char *ret_record,
                 size_t return_size, void *data) {
    /* Sanity check */
    assert(word_size <= return_size);
    assert(word != NULL);
    assert(ret_record != NULL);

    /* Copy the word */
    memcpy(ret_record, word, word_size);

    return E_ATTK_RECORD_NO_MATCH;
}


int make_dict_init(attack_st *attk_st, char *word_file_path,
                   char *dict_file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   uint32_t file_order, size_t rec_size) {
    file_st *file_in;
    file_st *file_out;

    file_in = malloc(sizeof(file_st));
    file_out = malloc(sizeof(file_st));

    read_word_list_init(file_in, word_file_path, WORDS_PER_THREAD, rec_size);

    /* Calculate record size */
    if (rec_size == 0) {
        file_in->open_file(file_in);
        file_in->close_file(file_in);
    }

    write_file_init(file_out, dict_file_path, "", file_order,
                    file_in->record_size);
    attack_st_init(attk_st, file_in, file_out, threads, do_make_dict, callback,
                   NULL, NULL);

    return 0;
}


int make_dict_destroy(attack_st *attack_st) {
    write_file_destroy(attack_st->file_out);
    read_word_list_destroy(attack_st->file_in);
    free(attack_st->file_in);
    free(attack_st->file_out);

    return 0;
}

