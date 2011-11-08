#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "syscall.h"

struct start_process_data
{
  char* file_name;
  struct semaphore load_done;
  bool success;
  struct wait_status *wait_status;
};

struct start_process_data *global_data;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
//   printf("testing, this is in process_execute\n");
  struct start_process_data data;
  char thread_name[15];
  tid_t tid;
  
  data.file_name = file_name;
  sema_init(&data.load_done,0);
  char* save_ptr;
  char* file_name_ = malloc(strlen(file_name)+1);
  strlcpy(file_name_,file_name,strlen(file_name)+1);
  char* fn_toke = strtok_r(file_name_," ",&save_ptr);
  int thread_name_length = 15;
  if((strlen(fn_toke)+1) < 15)
    thread_name_length = strlen(fn_toke)+1;
  strlcpy(thread_name,fn_toke,thread_name_length);
  free(file_name_);
  
  tid = thread_create(thread_name,PRI_DEFAULT,start_process,&data);
  
  if(tid != TID_ERROR)
  {
    sema_down(&data.load_done);
    if(data.success)
      list_insert(list_end(&thread_current()->children),&data.wait_status->elem);
      //list_push_back(&thread_current()->children,&data.wait_status->elem);
    else
      tid = TID_ERROR;
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
//   printf("testing, this is in start_process\n");
  struct start_process_data *data = file_name_;
  global_data = data;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (data->file_name, &if_.eip, &if_.esp);

  /* Allocate wait_status. */
  if(success)
  {
	data->wait_status = thread_current () ->wait_status = malloc (sizeof *data->wait_status);
	success = data->wait_status != NULL;
  }

  /*Initialize wait_status*/
  if(success)
  {
    data->wait_status->t = thread_current();
    data->wait_status->done = false;
    sema_init(&(data->wait_status->wait_status_sema),0);
    data->wait_status->status = -1;
	//TODO
  }

  /*Notify parent thread and clean up. */
  data->success = success;
  sema_up (&data->load_done);

    /* If load failed, quit. */
  //palloc_free_page (file_name);//does this need to stay here, it's not here in Project2SessionB
  if (!success) 
    sys_exit(-1);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  if(&if_ == NULL)
  {
    sys_exit(-1);
  }
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

bool
has_been_waited_on(tid_t child_tid, struct list children_waited_on)
{
  struct list_elem *e = list_head(&children_waited_on);
  if(!is_elem_tail(e->next))
  {
    struct child_has_been_waited_on *child;
    while(!(is_elem_tail(e)))
    {
      child = list_entry(e,struct child_has_been_waited_on,elem);
      if(child->child_tid == child_tid)
      {
	//printf("child->child_tid:%d,child_tid:%d\n",child->child_tid,child_tid);
	return true;
      }
    }
  }
  return false;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
//   printf("testing, this is in process_wait");
  struct thread *cur = thread_current();
  if(!(has_been_waited_on(child_tid,cur->children_waited_on)))
  {
    struct child_has_been_waited_on child;
    child.child_tid = child_tid;
    list_insert(list_end(&(cur->children_waited_on)),&(child.elem));
    struct list cur_children = cur->children;
    struct thread *child_to_wait_on = find_child_by_pid(cur_children,child_tid);
    if(child_to_wait_on == NULL)
    {
      return -1;
    }
    struct wait_status *local_wait_status = child_to_wait_on->wait_status;
    sema_down(&(local_wait_status->wait_status_sema));
    if(local_wait_status->done)
    {
      return local_wait_status->status;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static void init_stack(const char *file_name_,void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
//   printf("testing, this is in load\n");
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  char* save_ptr;
  char* file_name_ = malloc(strlen(file_name)+1);
  strlcpy(file_name_,file_name,strlen(file_name)+1);
  char* file_to_open = strtok_r(file_name_," ",&save_ptr);
  if(file_to_open == NULL)
  {
    free(file_name_);
    sys_exit(-1);
  }
  file = filesys_open (file_to_open);
  free(file_name_);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      sema_up(&(global_data->load_done));
      sys_exit(-1);
      goto done; 
    }
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  
  //push the arguments onto the stack. added by us.
  init_stack(file_name,esp);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(!success)
    file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
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

static void
init_stack(const char *file_name_,void **esp_)
{
  uint8_t **esp = (uint8_t**)esp_;
  char *fn;
  char *fn_toke;
  char *save_ptr;
  uint32_t count = 0;
  char* args[32];
  
  fn = malloc(strlen(file_name_)+1);
  strlcpy(fn,file_name_,strlen(file_name_)+1);
  fn_toke = strtok_r(fn," ",&save_ptr);
  if(fn_toke != NULL)
  {
    args[0] = malloc((strlen(fn_toke)+1)*sizeof(char));
    strlcpy(args[0],fn_toke,strlen(fn_toke)+1);
    count++;
    while(((fn_toke = strtok_r(NULL," ",&save_ptr))!=NULL)&&(count<32))
    {
      args[count] = malloc((strlen(fn_toke)+1));
      strlcpy(args[count],fn_toke,strlen(fn_toke)+1);
      count++;
    }
    
    int num_to_pad = 0;
    char pad = '\0';
    int for_i;
    int for_j;
    int argLength = 0;
    for(for_i = count - 1; for_i >= 0; for_i--)
    {
      argLength = strlen(args[for_i]);
      num_to_pad = 4 - (argLength%4);
      //printf("               args[%d]:%s,argLength:%d,num_to_pad:%d\n",for_i,args[for_i],argLength,num_to_pad);
      for(for_j = 0; for_j < num_to_pad; for_j++)
      {
	*esp -= 1;
	put_user(*esp,(uint8_t)pad);
      }
      for(for_j = argLength-1; for_j >= 0; for_j--)
      {
	*esp -= 1;
	put_user(*esp,args[for_i][for_j]);
      }
      args[for_i] = *esp;
    }
    
    uint32_t argLoc = 0;
    //pushing on a NULL sentinel
    *esp -= 1;
    put_user(*esp,(uint8_t)argLoc);
    *esp -= 1;
    put_user(*esp,(uint8_t)(argLoc));
    *esp -= 1;
    put_user(*esp,(uint8_t)(argLoc));
    *esp -= 1;
    put_user(*esp,(uint8_t)(argLoc));
    
    uint8_t to_push;
    for(for_i = count - 1; for_i >= 0; for_i--)
    {
      argLoc = (uint32_t)args[for_i];
      
      to_push = (uint8_t)(argLoc >> 24);
      *esp -= 1;
      put_user(*esp,(uint8_t)to_push);
      to_push = (uint8_t)(argLoc >> 16);
      *esp -= 1;
      put_user(*esp,(uint8_t)to_push);
      to_push = (uint8_t)(argLoc >> 8);
      *esp -= 1;
      put_user(*esp,(uint8_t)to_push);
      to_push = (uint8_t)(argLoc);
      *esp -= 1;
      put_user(*esp,(uint8_t)to_push);
    }
    
    argLoc = (uint32_t)*esp;
    to_push = (uint8_t)(argLoc >> 24);
    *esp -= 1;
    put_user(*esp,(uint8_t)to_push);
    to_push = (uint8_t)(argLoc >> 16);
    *esp -= 1;
    put_user(*esp,(uint8_t)to_push);
    to_push = (uint8_t)(argLoc >> 8);
    *esp -= 1;
    put_user(*esp,(uint8_t)to_push);
    to_push = (uint8_t)(argLoc);
    *esp -= 1;
    put_user(*esp,(uint8_t)to_push);
  }
  
  uint32_t argc = count;
  argc = argc << 24;
  *esp -= 1;
  put_user(*esp,(uint8_t)argc);
  argc = argc>>8;
  *esp -= 1;
  put_user(*esp,(uint8_t)(argc));
  argc = argc>>8;
  *esp -= 1;
  put_user(*esp,(uint8_t)(argc));
  argc = argc>>8;
  *esp -= 1;
  put_user(*esp,(uint8_t)(argc));
  
  *esp -= 4;
  
  //*esp -= 3;
  //*esp -= 3;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
