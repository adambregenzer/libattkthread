#SUBDIRS                         = python

noinst_LTLIBRARIES          = libattkthread.la libmakedict.la
libattkthread_la_SOURCES	= libattkthread.c brute_force.c queue.c read_file.c read_word_list.c write_file.c
libattkthread_la_LIBADD		= -lpthread -lrt
libmakedict_la_SOURCES		= libmakedict.c
libmakedict_la_LIBADD		= -lpthread -lrt libattkthread.la

