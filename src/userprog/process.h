#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool has_been_waited_on(tid_t child_tid, struct list children_waited_on);

#endif /* userprog/process.h */
