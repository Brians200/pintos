#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


/* Copies a byte from user address USRC to kernel address DST.
USRC must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
    : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}

struct file_descriptor
{
  int handle;
  char *file;
  struct list_elem elem;
};

static struct lock fs_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  printf("testing, this is in syscall_init\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

int sys_open(const char *ufile)
{
  //printf("testing, this is in sys_open");
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
  fd = malloc (sizeof *fd);
  if (fd != NULL)
  {
    lock_acquire (&fs_lock);
    fd->file = filesys_open (kfile);
    if (fd->file != NULL)
    {
      struct thread *cur = thread_current ();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }
    else
      free (fd);
    lock_release (&fs_lock);
  }
  palloc_free_page (kfile);
  return handle;
}

void sys_halt(void)
{
  //printf("testing, this is in sys_halt");
  shutdown_power_off();
}

void sys_exit(int status)
{
  //printf("testing, this is in sys_exit");
  //TODO: do some stuff with waiting or something
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n",cur->name,status);
  
  struct wait_status *local_wait_status = cur->wait_status;
  local_wait_status->done = true;
  local_wait_status->status = status;
  sema_up(&(local_wait_status->sema));
  list_remove(&local_wait_status->elem);
  
  struct list fds = cur->fds;
  struct list_elem *e;
  for(e=list_begin(&fds); e!=list_end(&fds); e=list_next(e))
  {
    file_close(list_entry(e,struct file_descriptor,elem)->file);
  }
}

pid_t sys_exec(const char*cmd_line)
{
  //printf("testing, this is in sys_exec");
  //TODO: do it
  return process_execute(cmd_line);
}

struct thread*
find_child_by_pid(struct list *children,pid_t pid)
{
  if(!list_empty(children))
  {
    struct list_elem *e;
    struct thread *cur_child;
    for(e = list_begin(children); e != list_end(children); e = list_next(e))
    {
      cur_child = list_entry(e,struct wait_status,elem)->t;
      if(cur_child->tid = pid)
	return cur_child;
    }
  }
  return NULL;
}

int sys_wait(pid_t pid)
{
  //printf("testing, this is in sys_wait");
  struct thread *cur = thread_current();
  struct list cur_children = cur->children;
  struct thread *child_to_wait_on = find_child_by_pid(&cur_children,pid);
  if(child_to_wait_on == NULL)
  {
    return -1;
  }
  struct wait_status *local_wait_status = child_to_wait_on->wait_status;
  sema_down(&(local_wait_status->sema));
  if(local_wait_status->done)
  {
    return local_wait_status->status;
  }
  else
  {
    return -1;
  }
  //TODO:how do we tell if the child was terminated by the kernel?
}

bool sys_create(const char *file, unsigned initial_size)
{
  //printf("testing, this is in sys_create");
  if(file == NULL)
    sys_exit(-1);
  return filesys_create(file,initial_size);
}

bool sys_remove(const char *file)
{
  //printf("testing, this is in sys_remove");
  if(file == NULL)
    sys_exit(-1);
  return filesys_remove(file);
}

struct file_descriptor*
get_file_descriptor(struct list fds,int fd)
{
  if(!list_empty(&fds))
  {
    struct list_elem *e;
    struct file_descriptor *retVal;
    for(e = list_begin(&fds); e != list_end(&fds); e = list_next(e))
    {
      retVal = list_entry(e,struct file_descriptor, elem);
      if(retVal->handle == fd)
	return retVal;
    }
  }
  return NULL;
}

int sys_filesize(int fd)
{
  //printf("testing, this is in sys_filesize");
  struct thread *cur = thread_current();
  struct list fds = cur->fds;
  struct file_descriptor *cur_fd = get_file_descriptor(fds,fd);
  if(cur_fd != NULL)
    return file_length(cur_fd->file);
  return -1;
}

int sys_read(int fd,void *buffer,unsigned size)
{
  //printf("testing, this is in sys_read");
  if(fd != 0)
  {
    struct file_descriptor *cur_fd = get_file_descriptor(thread_current()->fds,fd);
    if(cur_fd != NULL)
    {
      return file_read(cur_fd->file,buffer,size);
    }
    return -1;
  }
  else
  {
    //TODO: if it is 0 we need to read from input?
    input_init();
    while(size > 0)
    {
      
      size--;
    }
  }
  return -1;
}

int sys_write(int fd,const void *buffer,unsigned size)
{
  //printf("testing, this is in sys_write");
  if(fd != 1)
  {
    struct file_descriptor *cur_fd = get_file_descriptor(thread_current()->fds,fd);
    if(cur_fd != NULL)
    {
      return file_write(cur_fd->file,buffer,size);
    }
    return -1;
  }
  else
  {
    //TODO: if it is 1 we need to output to console, might have to break the output up?
    putbuf(buffer,size);
  }
  return -1;
}

void sys_seek(int fd,unsigned position)
{
  //printf("testing, this is in sys_seek");
  struct file_descriptor *cur_fd = get_file_descriptor(thread_current()->fds,fd);
  if(cur_fd != NULL)
  {
    file_seek(cur_fd->file,position);
  }
}

unsigned sys_tell(int fd)
{
  //printf("testing, this is in sys_tell");
  struct file_descriptor *cur_fd = get_file_descriptor(thread_current()->fds,fd);
  if(cur_fd != NULL)
  {
    return file_tell(cur_fd->file);
  }
  //TODO: what to return here if we reach this point?
  return 0;
}

void sys_close(int fd)
{
  //printf("testing, this is in sys_close");
  struct file_descriptor *cur_fd = get_file_descriptor(thread_current()->fds,fd);
  if(cur_fd != NULL)
  {
    file_close(cur_fd->file);
  }
  list_remove(cur_fd);
}

char*
copy_in_string(char* ufile_)
{
  size_t length;
  char *kfile = palloc_get_page(0);
  char *ufile = ufile_;
  if(kfile == NULL)
    thread_exit();
  for(length = 0;length < PGSIZE;length++)
  {
    if(!is_user_vaddr(ufile) || !get_user(kfile + length,ufile++))
    {
      palloc_free_page(kfile);
      thread_exit();
    }
    if(kfile[length] == '\0')
      return kfile;
  }
  
  kfile[PGSIZE-1] = '\0';
  return kfile;
}

void
copy_in (void *output, void *esp, unsigned size)
{
  uint32_t *dest = output;
  uint32_t *src = esp;
  for(;size>=0;size--,src++,dest++)
  {
    //what else do I have to do?
    if(!is_user_vaddr(src) || !get_user(dest,src))
    {
      thread_exit();
    }
  }
}

static void
syscall_handler (struct intr_frame *f)
{
  printf("testing, this is in syscall_handler\n");
  typedef int syscall_function (int, int, int);

  /* A system call. */
  struct syscall
  {
    size_t arg_cnt;
    /* Number of arguments. */
    syscall_function *func;
    /* Implementation. */
  };

  /* Table of system calls. */
  static const struct syscall syscall_table[] =
  {
    //Project 2
    {0, (syscall_function *) sys_halt},
    {1, (syscall_function *) sys_exit},
    {1, (syscall_function *) sys_exec},
    {1, (syscall_function *) sys_wait},
    {2, (syscall_function *) sys_create},
    {1, (syscall_function *) sys_remove},
    {1, (syscall_function *) sys_open},
    {1, (syscall_function *) sys_filesize},
    {3, (syscall_function *) sys_read},
    {3, (syscall_function *) sys_write},
    {2, (syscall_function *) sys_seek},
    {1, (syscall_function *) sys_tell},
    {1, (syscall_function *) sys_close}
  };
  
  const struct syscall *sc;
  unsigned call_nr;
  int args[3];
  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    thread_exit ();
  sc = syscall_table + call_nr;
  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}
