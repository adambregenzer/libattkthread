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

#include <Python.h>
#include "structmember.h"
#include "../../config.h"
#include "../libattkthread.h"


#define MAKE_STR(x)               X_MAKE_STR(x)
#define X_MAKE_STR(x)             #x


static PyMemberDef libattk_members[] = {
    {NULL}  /* Sentinel */
};

static PyObject *libattk_copy_error(attack_class_st *self) {
    PyErr_SetString(PyExc_TypeError, "This type is not copyable.");
    return NULL;
}

static PyObject *libattk_reduce_error(attack_class_st *self) {
    PyErr_SetString(PyExc_TypeError, "This type can not be reduced.");
    return NULL;
}

static PyObject *libattk_check_attack(attack_class_st *self) {
    attack_status status;
    char *result = NULL;
    PyObject *check_dict = NULL;
    int retval;

    #ifdef DEBUG
    printf("libattk_check_attack: START\n");
    #endif

    check_dict = PyDict_New();
    memset(&status, 0, sizeof(attack_status));

    if (self->attk_st.file_in != NULL &&
        self->attk_st.file_in->record_size > 0) {
        result = malloc(self->attk_st.file_in->record_size);
        memset(result, 0, self->attk_st.file_in->record_size);
        status.result = result;
        status.result_size = self->attk_st.file_in->record_size;
    } else {
        status.result = result;
        status.result_size = 0;
    }

    retval = check_attack(&(self->attk_st), &status);
    #ifdef DEBUG
    printf("libattk_check_attack: result (%lu|%lu|%s)\n", status.records_tested,
           status.total_records, result);
    #endif

    /* Add records tested */
    PyDict_SetItemString(check_dict, "records_tested",
                         Py_BuildValue("i", status.records_tested));
    /* Add total records */
    PyDict_SetItemString(check_dict, "total_records",
                         Py_BuildValue("i", status.total_records));
    /* Add result */
    PyDict_SetItemString(check_dict, "result",
                         Py_BuildValue("s", result));
    free(result);

    if (retval == 0) {
        pthread_mutex_lock(&(self->attk_st.mut));
    }
    /* Add attack state */
    PyDict_SetItemString(check_dict, "attack_state",
                         Py_BuildValue("i", self->attk_st.state));
    /* Add attack error */
    PyDict_SetItemString(check_dict, "error",
                         Py_BuildValue("i", self->attk_st.error));
    /* Add attack error state */
    PyDict_SetItemString(check_dict, "error_state",
                         Py_BuildValue("i", self->attk_st.e_state));
    if (retval == 0) {
        pthread_mutex_unlock(&(self->attk_st.mut));
    }

    return check_dict;
}

static PyObject *libattk_stop_attack(attack_class_st *self) {
    #ifdef DEBUG
    printf("libattk_stop_attack START\n");
    #endif

    stop_attack(&self->attk_st);

    Py_RETURN_NONE;
}

static PyMethodDef libattk_methods[] = {
    {"initialize", (PyCFunction)attk_data_init_func, METH_VARARGS |
        METH_KEYWORDS, "Data init."
    },
    {"start", (PyCFunction)attk_start_func, METH_VARARGS | METH_KEYWORDS,
     "Data start."
    },
    {"check", (PyCFunction)libattk_check_attack, METH_NOARGS,
     "Data start."
    },
    {"stop", (PyCFunction)libattk_stop_attack, METH_NOARGS,
     "Data start."
    },
    {"__copy__", (PyCFunction)libattk_copy_error, METH_NOARGS,
     "Raises an error, this type is not copyable."
    },
    {"__reduce__", (PyCFunction)libattk_reduce_error, METH_NOARGS,
     "Raises an error, this type can not be reduced."
    },
    {"__getstate__", (PyCFunction)libattk_reduce_error, METH_NOARGS,
        "Raises an error, this type can not be reduced."
    },
    {NULL}  /* Sentinel */
};

static PyObject *libattk_getcallback(attack_class_st *self, void *closure) {
    #ifdef DEBUG
    printf("libattk_getcallback START\n");
    #endif
    if (self->callback != NULL) {
        Py_INCREF(self->callback);
    } else {
        PyErr_SetString(PyExc_AttributeError, "callback");
    }

    return self->callback;
}

static int libattk_setcallback(attack_class_st *self, PyObject *value,
                               void *closure) {
    #ifdef DEBUG
    printf("libattk_setcallback START (%p)\n", value);
    #endif

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "Cannot delete the callback attribute");
        return -1;
    }

    if (!PyCallable_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "The callback attribute value must be callable");
        return -1;
    }

    Py_XDECREF(self->callback);
    Py_INCREF(value);
    self->callback = value;
    #ifdef DEBUG
    printf("libattk_setcallback DONE (%p)\n", self->callback);
    #endif

    return 0;
}

static PyGetSetDef libattk_getseters[] = {
    {"callback",
     (getter)libattk_getcallback, (setter)libattk_setcallback,
     "callback",
     NULL},
    {NULL}  /* Sentinel */
};

static int libattk_traverse(attack_class_st *self, visitproc visit,
                            void *arg) {
    Py_VISIT(self->callback);
    return 0;
}

static int libattk_clear(attack_class_st *self) {
    Py_CLEAR(self->callback);
    return 0;
}

static void libattk_dealloc(attack_class_st *self) {
    #ifdef DEBUG
    printf("libattk_dealloc START\n");
    #endif

    /* TODO: Cleanup */

    if (self->in_weakreflist != NULL)
        PyObject_ClearWeakRefs((PyObject *)self);
    libattk_clear(self);
    self->ob_type->tp_free((PyObject *)self);
}

static PyObject *libattk_repr(attack_class_st *self) {
    #ifdef DEBUG
    printf("libattk_repr START\n");
    #endif
    size_t buf_len = strlen("attack_class") + 100;
    char buffer[buf_len];

    memset(buffer, 0, buf_len);
    PyOS_snprintf(buffer, buf_len, "<%s at %p>", "attack_class", self);

    return PyString_FromString(buffer);
}

static PyTypeObject AttackClass = {
    PyObject_HEAD_INIT(NULL)
    0,                              /* ob_size                       */
    ATTK_MODULE_NAME ".attack_class", /* tp_name                     */
    sizeof(attack_class_st),        /* tp_basicsize                  */
    0,                              /* tp_itemsize                   */
    (destructor)libattk_dealloc,    /* tp_dealloc                    */
    0,                              /* tp_print                      */
    0,                              /* tp_getattr                    */
    0,                              /* tp_setattr                    */
    0,                              /* tp_compare                    */
    (reprfunc)libattk_repr,         /* tp_repr                       */
    0,                              /* tp_as_number                  */
    0,                              /* tp_as_sequence                */
    0,                              /* tp_as_mapping                 */
    0,                              /* tp_hash                       */
    0,                              /* tp_call                       */
    0,                              /* tp_str                        */
    0,                              /* tp_getattro                   */
    0,                              /* tp_setattro                   */
    0,                              /* tp_as_buffer                  */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE
    | Py_TPFLAGS_HAVE_GC,           /* tp_flags                      */
    "",                             /* tp_doc                        */
    (traverseproc)libattk_traverse, /* tp_traverse                   */
    (inquiry)libattk_clear,         /* tp_clear                      */
    0,                              /* tp_richcompare                */
    offsetof(attack_class_st, in_weakreflist), /* tp_weaklistoffset  */
    0,                              /* tp_iter                       */
    0,                              /* tp_iternext                   */
    libattk_methods,                /* tp_methods                    */
    libattk_members,                /* tp_members                    */
    libattk_getseters,              /* tp_getset                     */
    0,                              /* tp_base                       */
    0,                              /* tp_dict                       */
    0,                              /* tp_descr_get                  */
    0,                              /* tp_descr_set                  */
    0,                              /* tp_dictoffset                 */
    0,                              /* tp_init                       */
    0,                              /* tp_alloc                      */
    PyType_GenericNew,              /* tp_new                        */
};

static PyMethodDef attk_plug_methods[] = {
    {NULL}        /* Sentinel */
};

static void build_dict(PyObject *m, char *var_name, char **args) {
    PyObject *new_dict;
    PyObject *arg;
    char *type;
    char *name;
    char *description;
    int state;

    new_dict = PyDict_New();
    while (1) {
        name = type = description = NULL;
        state = 0;
        while (*args != NULL) {
            switch (state) {
            case 0:
                name = *args;
                break;
            case 1:
                type = *args;
                break;
            case 2:
                description = *args;
                break;
            }
            args++;
            state++;
            if (state == 3) break;
        }
        if (name == NULL) {
            break;
        } else {
            arg = Py_BuildValue("(ss)", type, description);
            PyDict_SetItemString(new_dict, (const char *)name, arg);
        }
    }
    PyModule_AddObject(m, var_name, new_dict);
}

PyMODINIT_FUNC ATTK_INIT_FUNC(void) {
    PyObject *m;

    #ifdef DEBUG
    printf("ATTK_INIT_FUNC (%s) START\n", MAKE_STR(ATTK_INIT_FUNC));
    #endif

    if (PyType_Ready(&AttackClass) < 0)
        return;

    m = Py_InitModule3(ATTK_MODULE_NAME, attk_plug_methods, ATTK_MODULE_DOC);

    build_dict(m, "init_args", attk_data_init_args_d);
    build_dict(m, "start_args", attk_start_args_d);

    Py_INCREF(&AttackClass);
    PyModule_AddObject(m, "attack_class", (PyObject *)&AttackClass);
}

