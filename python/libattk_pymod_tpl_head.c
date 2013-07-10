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

#undef _GNU_SOURCE
#include <Python.h>
#include "structmember.h"

typedef struct {
    PyObject_HEAD

    PyObject *callback;                         /* Stored callback method    */
    PyObject *in_weakreflist;                   /* weakref support           */

    attack_st attk_st;                          /* threaded attack structure */
    int (*attack_st_destroy)(attack_st *attack_st); /* attack_st destructor  */

    ATTK_TYPE_DATA_STRUCT attack_data;          /* Attack data               */
} attack_class_st;


int libattk_py_callback(attack_st *fargs) {
    PyObject *callback;             /* Python callback function */
    attack_status status;           /* Attack result status     */
    char *result;                   /* Result buffer            */
    PyObject *py_status = NULL;     /* Callback Arguments       */
    PyObject *py_result = NULL;     /* Callback result          */
    PyGILState_STATE py_state;      /* Python State             */

    #ifdef DEBUG
    printf("libattk_py_callback: START (%p)\n", fargs->callback_data);
    #endif

    /* Make sure we can call python */
    #ifdef DEBUG
    printf("libattk_py_callback: grabbing python\n");
    #endif
    py_state = PyGILState_Ensure();

    /* Setup result buffer */
    result = malloc(fargs->file_in->record_size);
    memset(result, 0, fargs->file_in->record_size);

    /* Setup status structure */
    memset(&status, 0, sizeof(attack_status));
    status.result = result;
    status.result_size = fargs->file_in->record_size;

    /* Get final status information */
    check_attack(fargs, &status);

    /* Create python callback argument list */
    if (status.result != NULL) {
        py_status = Py_BuildValue("(iis)", status.records_tested,
                                  status.total_records, status.result);
    } else {
        py_status = Py_BuildValue("(iis)", status.records_tested,
                                  status.total_records, "");
    }

    /* Get callback */
    callback = fargs->callback_data;

    /* Check callable and, if possible, call the python callback method */
    #ifdef DEBUG
    printf("libattk_py_callback: calling python function (%p)\n", callback);
    #endif
    if (callback != NULL) {
        if (!PyCallable_Check(callback)) {
            PyErr_SetString(PyExc_TypeError,
                            "The callback attribute value must be callable");
            return -1;
        }
        py_result = PyObject_Call(callback, py_status, NULL);
    }

    /* Cleanup */
    Py_DECREF(py_status);
    free(result);

    /* Free python callback result */
    Py_XDECREF(py_result);

    /* PyGILState_Release(py_state); */

    /* Return */
    #ifdef DEBUG
    printf("libattk_py_callback: DONE\n");
    #endif
    if (py_result == NULL) {
        return -1;
    }
    return 0;
}

