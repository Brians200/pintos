#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../lib/user/syscall.h"

void syscall_init (void);
int sys_open(const char *ufile);
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char*cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd,void *buffer,unsigned size);
int sys_write(int fd,const void *buffer,unsigned size);
void sys_seek(int fd,unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
char* copy_in_string(char *ufile);
void copy_in (void *output, void *esp, unsigned size);

//static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
//static inline bool put_user (uint8_t *udst, uint8_t byte);
#endif /* userprog/syscall.h */
