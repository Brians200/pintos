#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "threads/vaddr.h"

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
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

int sys_open(const char *ufile)
{
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
  shutdown_power_off();
}

void sys_exit(int status)
{
//TODO: do some stuff with waiting or something
  
  printf("%s: exit(%d)\n",thread_current()->name,status);
}

pid_t sys_exec(const char*cmd_line)
{
  	
}

int sys_wait(pid_t pid)
{
  
}

bool sys_create(const char *file, unsigned initial_size)
{
  
}

bool sys_remove(const char *file)
{
  
}

int sys_filesize(int fd)
{
  
}

int sys_read(int fd,void *buffer,unsigned size)
{
  
}

int sys_write(int fd,const void *buffer,unsigned size)
{
  
}

void sys_seek(int fd,unsigned position)
{
  
}

unsigned sys_tell(int fd)
{
  
}

void sys_close(int fd)
{
  
}

char*
copy_in_string(char* ufile_)
{
  //int size = strlen(ufile);
  size_t length;
  char *kfile = palloc_get_page(0);
  char *ufile = ufile_;
  if(ks == NULL)
    thread_exit();
  for(length = 0;length < PGSIZE;length++)
  {
    if(!is_user_vaddr(ufile) || !get_user(kfile + length,ufile++))
    {
      palloc_free_page(ks);
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
