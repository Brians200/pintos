#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static struct lock fs_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
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
