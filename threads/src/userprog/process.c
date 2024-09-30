#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <list.h> 
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"


static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp, struct pthread* curr, void* sfun);


/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current(); 
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1); // has memory leak here if not freed later accordingly
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
struct start_cmd {
  char* file_name;
  struct semaphore process_sema;
  struct list *children;
  bool has_exec;
};


pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /*  Make a copy of FILE_NAME.
      Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Find the position of the first space in the sentence. */
  size_t i = 0;
  while (file_name[i] != ' ' && file_name[i] != '\0') {
    i++;
  }
  char* prog_name = malloc(sizeof(char)*(i+1));
  strlcpy(prog_name, file_name, i+1);
  
  struct start_cmd start_cmd;
  start_cmd.file_name = fn_copy;
  sema_init(&(start_cmd.process_sema), 0);
  start_cmd.children = &(thread_current() -> pcb -> children);
  start_cmd.has_exec = thread_current()->pcb->has_exec;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(prog_name, PRI_DEFAULT, start_process, &start_cmd);
  
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  /* Down the process_sema; wait for child process to finish loading. */
  sema_down(&(start_cmd.process_sema));

  /* Removes the front element from LIST and returns it.
   Undefined behavior if LIST is empty before removal. */
  struct shared_data *child_data = find_shared_data(&(thread_current() -> pcb -> children), tid);
  if (child_data == NULL) {
    return -1;
  }

  if (child_data -> load == false) {
    list_pop_front(start_cmd.children);
    free(child_data);
    return -1;
  } 

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* start_cmd) {
  struct start_cmd* child_cmd = (struct start_cmd*) start_cmd;
  char* file_name = (char*)child_cmd->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  bool fd_table_success;
  bool shared_data_success;

  /* Allocate process control block. */
  struct process* new_pcb = calloc(sizeof(struct process), 1);
  struct fd_table *new_fd_table = calloc(sizeof(struct fd_table), 1);
  struct shared_data *new_shared_data = calloc(sizeof(struct shared_data), 1);

  pcb_success = new_pcb != NULL;
  fd_table_success = new_fd_table != NULL;
  shared_data_success = new_shared_data != NULL; 

  success = pcb_success && fd_table_success && shared_data_success;
 
  /* Initialize process control block. */
  if (success) {
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    /* Initialize child list, semaphore, shared data, and FD table. */
    list_init(&(new_pcb -> children));
    sema_init(&(new_pcb -> list_sema), 0);
    init_table(new_fd_table);
    init_shared_data(new_shared_data);
    list_init(&(new_pcb->pthread_list)); // for pthreads
    sema_init(&(new_pcb->pthread_exit_sema), 0);
    list_init(&(new_pcb->joinable_pthreads));

    size_t size = list_size(&(new_pcb->pthread_list));
  
    new_pcb -> fd_table = new_fd_table;
    new_pcb -> shared_data = new_shared_data;

    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    if(child_cmd->has_exec == false) list_init(child_cmd -> children);
    list_push_front(child_cmd -> children, &(new_shared_data -> elem));
    new_pcb->has_exec = true;

    list_init(&new_pcb->user_locks);
    list_init(&new_pcb->user_semas);
  }

  char *token, *save_ptr;
  int argc = 0;
  char* temp_cmd_line = calloc(strlen(file_name) + 1, 1);
  strlcpy(temp_cmd_line, file_name, strlen(file_name)+1);

  for (token = strtok_r(temp_cmd_line, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
    argc = argc + 1;
  }

  free(temp_cmd_line);

  char* argv[argc+1];
  argc = 0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
    argv[argc++] = token;
  }
  argv[argc] = NULL;

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv[0], &if_.eip, &if_.esp);
    new_shared_data -> load = success;
  }

  /* Save FPU state for first Pintos process. */
  volatile char temp_buffer[108];
  asm volatile("fnsave (%0)" :: "g"(temp_buffer));
  
  /* Initialize FPU state for new process. */
  asm volatile("fninit");
  asm volatile("fnsave (%0)" :: "g"(&(if_.fpu_state_buffer)));
  
  /* Restor FPU state for first Pintos process. */
  asm volatile("frstor (%0)" :: "g"(temp_buffer));


  if (success) {
    char* argv_addr[argc];
    for (int i = 0 ; i < argc ; i++) {
      if_.esp = if_.esp - (strlen(argv[i]) + 1);
      argv_addr[i] = (char *) if_.esp;
      memcpy(if_.esp, argv[i], strlen(argv[i])+1);
    }

    /* 
      Add padding to align the stack. 
      The number of pointers to be stacked is equal to 1(null)+argc (argv pointers) + 1(argv) + 1 argc(1).
      Each pointer is 4 bytes since it is 32bit architecture. */
    uint32_t stack_align_offset = (uint32_t)(if_.esp - ((uint32_t)argc + 3)*4)%16;
    if_.esp = if_.esp - stack_align_offset;
    memset(if_.esp, 0, stack_align_offset);

    /* Add null pointer sentinel. */
    if_.esp = if_.esp - sizeof(char*);
    memset(if_.esp, argv[argc], sizeof(char*));


    /* Stack pointers(argv[i]) in reverse order. */
    for (int i = 0 ; i < argc ; i++) {
      if_.esp = if_.esp - sizeof(char*);
      //memcpy(if_.esp, &argv_addr[argc-i-1], sizeof(char*));
      *(int *)if_.esp = (uint32_t) argv_addr[argc - i - 1];
    }

    // stack argv
    //char *ptr = *if_.esp;
    if_.esp = if_.esp - sizeof(char*);
    char *prev = (char *)(if_.esp + (uint32_t)4);
    memcpy(if_.esp, &prev, sizeof(char*)); // memcpy?
    //*(char**)if_.esp = *(char**)(if_.esp + 4);
    
    // stack argc
    if_.esp = if_.esp - sizeof(int); // argv_addr must be 16 bytes aligned meaning the last hex digit should be 0
    memset(if_.esp, argc, sizeof(int));
    *(int *)if_.esp = argc;

    // stack fake address
    if_.esp = if_.esp - sizeof(void*);
    memset(if_.esp, '\0', sizeof(void*));
  }


  /* Handle failure with successful fd_table malloc. Must free fd_table*/
  if (!success) {

    if (fd_table_success) {
      free_table(t->pcb->fd_table);
    }
    if (shared_data_success) {
      new_shared_data -> ref_count -= 1;
    }
    if (pcb_success) {
      struct process* pcb_to_free = t->pcb;
      t->pcb = NULL;
      free(pcb_to_free);
    }
  }

  /* After load, let the parent process know that it can stop blocking */
  sema_up(&child_cmd->process_sema);

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    //sema_up(&temporary);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {

  struct process *pcb = thread_current() -> pcb;
  struct list *children = &(pcb -> children);

  struct shared_data *child_data = find_shared_data(children, child_pid); // change; error starts here 
  if (!child_data) return -1;

  /*Checks if parent has called wait on the child before */
  if (child_data -> waited_on) return -1;
  child_data -> waited_on = true;

  /* If reference count is 1, then child has exited */
  if (child_data -> ref_count <= 1) {
    return child_data -> exit_code;
  }

  sema_down(&(child_data -> wait_sema));
  int exit_status = child_data -> exit_code;

  return exit_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  wake_up_pthreads_joined_on_main();
  wake_up_pthread_waiters();
  signal_pthread_death(); // might be better flagged elsewhere
  free_user_semas();
  free_user_locks();

  struct list *pthread_list = &(cur->pcb->pthread_list);

  while(!list_empty (pthread_list)) {
    // struct pthread* p = list_pop_front(pthread_list);
    struct list_elem* e = list_pop_front(pthread_list);
    struct pthread* p = list_entry(e, struct pthread, pthread_elem);
    if (!p->terminated) {
      // block till pthread dies
      sema_down(&(cur->pcb->pthread_exit_sema));
    }
    free(p);
  }
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  sema_up(&(cur->pcb->shared_data->wait_sema));

  free_table(pcb_to_free->fd_table);
  file_allow_write(pcb_to_free->cur_file);
  file_close(pcb_to_free->cur_file);
  pcb_to_free->shared_data->ref_count -= 1; // change
  if (pcb_to_free->shared_data->ref_count == 0) { // likely not created in the first place with malloc
    free(pcb_to_free->shared_data);
  }
  // todo: check that open pthreads are closed / freed
  cur->pcb = NULL;
  free(pcb_to_free); // crashes here
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  file_deny_write(file);
  t->pcb->cur_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
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
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
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
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
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
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}


void init_shared_data(struct shared_data* shared_data) {
  shared_data->pid = thread_current()->tid;
  shared_data->load = false;
  shared_data->ref_count = 2;
  shared_data->exit_code = -1;
  sema_init(&(shared_data->wait_sema), 0);
  shared_data -> waited_on = false; 
}

struct shared_data *find_shared_data(struct list *children, int pid) {
  struct list_elem* e;
  struct list *all_list_ptr = children;
  for (e = list_begin(all_list_ptr); e != list_end(all_list_ptr); e = list_next(e)) {
    struct shared_data* shared_data = list_entry(e, struct shared_data, elem); // c
    if ((shared_data -> pid) == pid) return shared_data;
  }
  return NULL;
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void), void** esp, struct pthread* curr, void* sfun) { 
  // eip as stub
  // typedef void (*pthread_fun)(void*);
  // typedef void (*stub_fun)(pthread_fun, void*);
  /* Initialize thread. */
  if (esp == NULL) {
    return false;
  }
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    uint8_t* base = (uint8_t*)PHYS_BASE;
    for (int i = 1; !success; i += 1) { // TODO: add check for not infinitely checking for free space
      // simply iteratively checks for the next free page; can be optimized
      // could alternatively iterate based on # of threads but would skip over freed memory of exited threads
      success = install_page(((uint8_t*)PHYS_BASE) - (PGSIZE * i), kpage, true);
      //base = (uint8_t*)PHYS_BASE - (PGSIZE * (i - 1));
      base = (uint8_t*)PHYS_BASE - (PGSIZE * i);
      // TODO: if there is a page fault in trying to access user stack, check if process has been activated
    }
    *esp = base + PGSIZE; 
    // TODO: add false condition
    // palloc_free_page(kpage);
    curr -> user_stack = base;
  }
  
  //curr->user_stack = kpage;

  // eip is _pthread_start_stub(pthread_fun fun, void* arg)
  *eip = (void (*)(void))sfun; // might have typecast error here
  return success;
}

/* Used to make sure parent thread doesn't exit pthread_execute until child thread starts */
struct semaphore pthread_sema;

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) { 
  struct thread* t = thread_current();
  //process_activate();

  sema_init(&pthread_sema, 0);
  // void* exec_[] = {&sf, &tf, arg, &pthread_sema}; // todo: possible bug might be sending arg and not &arg; should double check
  void* exec_[] = {sf, tf, arg, &pthread_sema}; // 
  // strlcat(char *dst, const char *src, size_t size); 
  // char name_helper[2] = {(char)(thread_current()->tid), '\0'};
  
  // char* name = strlcat("p_", name_helper, strlen(name_helper));
  // give the same name as current thread for simplicity in testing
  char* name = t->name;

  // strcat(strcat(strcat("p", itoa(thread_current()->tid)), "_c")); 
  // format would ideally be: p#_c#, or parent # _ child #; currently set to just p#_c for convenience atm
  tid_t tid;
  tid = thread_create(name, PRI_DEFAULT, start_pthread, &exec_);
  if (tid == TID_ERROR) {
    return -1;
  }
  // todo: add semas to block while setting up pthread
  sema_down(&pthread_sema);

  return tid;
  // activate pcb pagedir or else cannot write to stack
  // let exec_ = {&stub, &func, &args} for call to start_pthread
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_) {
  // let exec_ = {&stub, &func, &args}

  // kernel thread that creates user thread 
  // (kernel thread masked as user thread; switch based on trap from userspace)
  struct thread* t = thread_current();
  // pagedir_activate(t->pcb->pagedir);
  //process_activate();
  /// CURRENTLY HERE
  // what is exec_? the executable?
  uint32_t* setup_args = (uint32_t*)exec_;
  struct intr_frame if_;
  bool success;

  /* Allocate pthread. */
  struct pthread* curr = calloc(sizeof(struct pthread), 1);

  success = curr != NULL;
 
  if (success) {
    /* Initialize pthread. */
    sema_init(&(curr -> user_sema), 0); // set to 0?
    curr->has_joined = false;
    curr->kernel_thread = thread_current();
    curr->tid = curr->kernel_thread->tid; // necessary for when the kernel thread is exited but we still need the pthread wrapper
    // curr->kernel_thread->to_be_killed = false; // automatically set in to_be_killed
    curr->terminated = false;
    curr->waiting_on = NULL;
    curr->main_thread = curr->kernel_thread->pcb->main_thread;
    
    size_t size = list_size(&(curr->kernel_thread->pcb->pthread_list));
    list_push_back(&(curr->kernel_thread->pcb->pthread_list), &(curr->pthread_elem));
    
    size = list_size(&(curr->kernel_thread->pcb->pthread_list));
    list_push_back(&(curr->kernel_thread->pcb->joinable_pthreads), &(curr->joinable_pthread_elem));

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = setup_thread(&if_.eip, &if_.esp, curr, (void*)setup_args[0]);
    if_.eip = setup_args[0]; // Set instruction pointer to the stub
  }

  /* Stack Arguments */
  
  if (success) {
    // stack args
    // Push func and args onto the stack
    // int argc = 3; //let setup_args = {&stub, &func, &args}
    // char* argv_addr[argc];
    // for (int i = 1 ; i < argc ; i++) {
    //   if_.esp = if_.esp - sizeof(setup_args[i]);
    //   argv_addr[i] = (char *) if_.esp;
    //   memcpy(if_.esp, (void*)setup_args[i], sizeof(setup_args[i]));
    // }

    /* Align stack */
    if_.esp = (uint8_t *) if_.esp - 8;
    
    /* Push args onto stack */
    if_.esp = (uint8_t *) if_.esp - sizeof(void *);
    memcpy(if_.esp, &setup_args[2], sizeof(void *));

    /* Push func onto stack */
    if_.esp = (uint8_t *) if_.esp - sizeof(void *);
    memcpy(if_.esp, &setup_args[1], sizeof(void *));

    /* Push fake return address */
    if_.esp = (uint8_t *) if_.esp - sizeof(void *);
    memset(if_.esp, 0, sizeof(void *));

    // /* 
    //   Add padding to align the stack. 
    //   The number of pointers to be stacked is equal to 1(null)+argc (argv pointers) + 1(argv) + 1 argc(1).
    //   Each pointer is 4 bytes since it is 32bit architecture. */
    // uint32_t stack_align_offset = (uint32_t)(if_.esp - ((uint32_t)argc + 3)*4)%16;
    // if_.esp = if_.esp - stack_align_offset;
    // memset(if_.esp, 0, stack_align_offset); 
    // // /* Sets the SIZE bytes in DST to VALUE. */ 
    // // void* memset(void* dst_, int value, size_t size)

    // /* Add null pointer sentinel. */
    // if_.esp = if_.esp - sizeof(setup_args[0]);
    // memset(if_.esp, NULL, sizeof(setup_args[0])); // all pointers


    // /* Stack pointers(argv[i]) in reverse order. */
    // for (int i = 0 ; i < argc ; i++) {
    //   if_.esp = if_.esp - sizeof(setup_args[0]);
    //   //memcpy(if_.esp, &argv_addr[argc-i-1], sizeof(char*));
    //   *(int *)if_.esp = (uint32_t) argv_addr[argc - i - 1];
    // }

    // // stack argv
    // //char *ptr = *if_.esp;
    // if_.esp = if_.esp - sizeof(setup_args[0]);
    // void* prev = (void*)(if_.esp + (uint32_t)4);
    // memcpy(if_.esp, &prev, sizeof(setup_args[0])); // memcpy?
    // //*(char**)if_.esp = *(char**)(if_.esp + 4);
    
    // // stack argc
    // if_.esp = if_.esp - sizeof(int); // argv_addr must be 16 bytes aligned meaning the last hex digit should be 0
    // memset(if_.esp, argc, sizeof(int));
    // *(int *)if_.esp = argc;

    // // stack fake address
    // if_.esp = if_.esp - sizeof(void*);
    // memset(if_.esp, '\0', sizeof(void*));
  }


  /* Handle failure with successful fd_table malloc. Must free fd_table*/
  if (!success) {
    if (curr != NULL) {
      if(curr->user_stack != NULL) {
        pagedir_clear_page(t->pcb->pagedir, curr->user_stack);
        palloc_free_page(curr->user_stack);
      }
      free(curr);
    }
    /* After load, let the parent process know that it can stop blocking */
    // todo:
    // sema_up(&child_cmd->process_sema);
    // (not necessary here since no new executable loaded)
    sema_up(setup_args[3]);
    thread_exit();
  }

  /* After load, let the parent process know that it can stop blocking */
  // todo:
  // sema_up(&child_cmd->process_sema);
  sema_up(setup_args[3]);

  size_t size = list_size(&(curr->kernel_thread->pcb->pthread_list));

  thread_yield();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) { 
  // Note: pthread_join and pthread_exit are necessary for passing the create-simple test
  // sema_down(&(child_data -> wait_sema));
  // int exit_status = child_data -> exit_code;

  // return exit_status;

  struct thread* curr = thread_current();
  struct pthread* p = get_joinable_pthread(curr, tid); // make a find_joinable_pthread struct 
  //struct pthread* p = find_pthread(curr, tid);
  //size_t size = list_size(&(p->kernel_thread->pcb->pthread_list));

  if (p == NULL) {
    return TID_ERROR;
  }
  else if (p->has_joined) {
    return TID_ERROR;
  }
  else if (curr->pcb->main_thread != p->main_thread) {
    return TID_ERROR; // need to be from same process
    // what if already terminated but not from same thread?
    // accounts for that
  }
  else if (p->terminated) { 
    // sema_down(&(p -> user_sema)); // already dead so sema_down would never happen
    p->has_joined = true;
    return p->tid;
  }
  // if (p->kernel_thread->tid == tid) return TID_ERROR; // causes page error
  // wait on thread with TID to exit
  p->has_joined = true;
  list_remove(&(p->joinable_pthread_elem));
  p->waiting_on = p->kernel_thread;
  sema_down(&(p -> user_sema));
  p->waiting_on = NULL;;
  return p->tid;
}



/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  // todo: edit for terminated stuff (track termination status w/o freeing info; see: thread_exit)
  struct thread* curr = thread_current();
  struct pthread* pthread_curr = find_pthread(curr, curr->tid);
  if (pthread_curr->terminated) return;
  // deallocate the user stack by removing page directory mapping and freeing palloced page
  pagedir_clear_page(curr->pcb->pagedir, pthread_curr->user_stack);
  void *phys_addr = pagedir_get_page(curr->pcb->pagedir, pthread_curr->user_stack);
  palloc_free_page(phys_addr);
  //palloc_free_page(pthread_curr->user_stack);
   // might need to move till after clearing pages
  pthread_curr->terminated = true;
  // remove from pthread_list and free pthread struct only in pthread_exit_main

  // if (pthread_curr->has_joined) { // changes for join-exit-1
  //   sema_up(&(pthread_curr->user_sema));
  // }
  if (pthread_curr->has_joined) {
    sema_up(&(pthread_curr->user_sema));
  }
  else if (pthread_curr->kernel_thread->to_be_killed) {
    struct semaphore* sema = &(pthread_curr->kernel_thread->pcb->pthread_exit_sema);
    sema_up(sema);
  }


  // todo: remove any related waiters + free related locks for this
  thread_exit();
  // current issue 
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  // Grading comment: pthread_exit_main must first wake any waiters, 
  // then join on all unjoined threads. Then, simply call process_exit.
  // 
  // todo: grab the process level lock (whenever handling process-level stuff)
  // todo: wake all waiters
  // user level lock (sema, etc.) get ID to grab it (like in FD table)
  // lock_acquire(&global_lock);
  struct list* pthread_list = &(thread_current()->pcb->pthread_list);

  tid_t designated = thread_current()->tid;
  size_t size = list_size(&(thread_current()->pcb->pthread_list));

  // wake up all waiters
  wake_up_pthread_waiters();
  size = list_size(&(thread_current()->pcb->pthread_list));

  while(!list_empty(pthread_list)) {
    size = list_size(pthread_list); // why does it error here???
    struct list_elem* e = list_pop_front(pthread_list);
    struct pthread* p = list_entry(e, struct pthread, pthread_elem);
    tid_t tid = p->tid;
    if (p->waiting_on == p->main_thread) {
      sema_up(&(p->user_sema));
    }
    if (tid != designated) { // todo
    // if (p->kernel_thread->tid != designated && is_trap_from_userspace(struct intr_frame* frame)) {
      tid_t ret = pthread_join(tid);
    }
    // list_remove(&(p->pthread_elem)); // editing a list while iterating causes problems
    // free before joining or it's never called
    // free(p);
  }

  // struct pthread* p = list_entry(list_pop_front(&pthread_list), struct pthread, pthread_elem);
  // ASSERT(list_empty(&pthread_list));
  // free(p); // leftover thread is NOT pthread; main thread = kernel thread 
  // lock_release(&global_lock);
  // todo: in pthread exit syscall handler, before exiting, check if only 1 thread / lock remaining (can use cond_wait condition variable)
  process_exit();

  // whoever calls process exit = designated exiter = killed last
  // threads interrupted by timer → can wait for interrupt handler to check if thread is trap from user space → direct to pthread_exit
  // >> need to check if from user space first (if already in kernel, can accidentally call pthread exit twice)
  // todo: in pthread exit syscall handler, before exiting, check if only 1 thread / lock remaining (can use cond_wait condition variable)
}

/* 
    Looks for the FD list_elem with the FD number N. 
    Returns NULL if there is no list_elem with the FD number N. 
    Works by iterating from beginning to end to find
*/
struct fd* find(struct fd_table* fd_table, int fd) {
    for (struct list_elem* e = list_begin(&fd_table->fds); e != list_end(&fd_table->fds); e = list_next(e)) {
        struct fd* file_desc = list_entry(e, struct fd, list_fd);
        if (file_desc != NULL && file_desc->val == fd) {
            return file_desc;
        }
    } 
    return NULL;
}


/*
    Removes the given FD from the FD table. Returns -1 if it does not exist. 
*/
int remove(struct fd_table* fd_table, int fd) {
    struct fd* file_desc = find(fd_table, fd);
    if (file_desc == NULL) {
        return -1;
    }
    struct list_elem* e = &(file_desc->list_fd);
    list_remove(e);
    free(file_desc);
    return 0;
}

/*
    Adds the given FD to the FD table. Returns the FD.
*/
struct fd* add(struct fd_table* fd_table, struct file* file) {
  struct fd* file_descriptor = calloc(sizeof(struct fd), 1); 
  struct list_elem* e = &(file_descriptor->list_fd);
  file_descriptor->val = fd_table->next_unused_fd;
  file_descriptor->file = file;
  fd_table->next_unused_fd += 1;
  list_push_back(&(fd_table->fds), e);
  file_descriptor->list_fd = *e;
  return file_descriptor;
}

/* 
    Returns the file pointer associated with the given FD.
*/
struct file* get_file_pointer(struct fd_table *fd_table, int fd) {
    return find(fd_table, fd)->file;
}


/*
    Initializes FD table.
*/    
void init_table(struct fd_table *fd_table) {
    struct list* fds = &(fd_table->fds);
    list_init(fds);
    fd_table->fds = *fds;
    fd_table->next_unused_fd = 2;
}


void free_table(struct fd_table *fd_table) {
    struct list_elem* curr;

    while(!list_empty (&(fd_table->fds))) {
        curr = list_pop_front(&(fd_table->fds));
        free(curr);
    }
    free(fd_table);
} 


struct pthread* find_pthread(struct thread* t, tid_t tid) { // can rewrite these to use generics instead
  struct list *pthread_list = &(t->pcb->pthread_list);
  // size_t size = list_size(pthread_list);
  for (struct list_elem* e = list_begin(pthread_list); e != list_end(pthread_list); e = list_next(e)) {
        struct pthread* p = list_entry(e, struct pthread, pthread_elem);
        tid_t p_tid = p->tid;
        if (p_tid == tid) {
            return p;
        }
    } 
  return NULL;
}

// Used when process_exit is called. Sets pthread flag to_be_killed to true for all pthreads. 
// pthreads running kernel code are also killed once they return to userspace. 
void signal_pthread_death(void) {
  struct list *pthread_list = &(thread_current()->pcb->pthread_list);
  for (struct list_elem* e = list_begin(pthread_list); e != list_end(pthread_list); e = list_next(e)) {
      struct pthread* p = list_entry(e, struct pthread, pthread_elem);
      if (!p->terminated) { // if the kernel thread has already been exited, then do nothing for this pthread
        struct thread* t = p->kernel_thread;
        t->to_be_killed = true;
        release_all_locks_held(t);
        //thread_unblock(t);
      }
    } 
}


// Wakes up the pthreads that were joined on the main thread
void wake_up_pthreads_joined_on_main(void) {
  struct thread* curr = thread_current(); 
  struct thread* main_thread = curr->pcb->main_thread;
  struct list *pthread_list = &(curr->pcb->pthread_list);
  // size_t size = list_size(pthread_list);
  for (struct list_elem* e = list_begin(pthread_list); e != list_end(pthread_list); e = list_next(e)) {
    struct pthread* p = list_entry(e, struct pthread, pthread_elem);
    if (p->waiting_on == main_thread) { 
    // if the kernel thread has already been exited, then do nothing for this pthread
      if (!p->terminated) {
        p->waiting_on = NULL;
        sema_up(&(p->user_sema));
        // thread_unblock(p->kernel_thread); // does it automatically schedule them?
      }
    } 
  }
}

void wake_up_pthread_waiters(void) { // from joins
  struct list *pthread_list = &(thread_current()->pcb->pthread_list);
  // size_t size = list_size(pthread_list);
  for (struct list_elem* e = list_begin(pthread_list); e != list_end(pthread_list); e = list_next(e)) {
    struct pthread* p = list_entry(e, struct pthread, pthread_elem);
    if (!p->terminated && p->waiting_on != NULL) {
      p->waiting_on = NULL;
      sema_up(&(p->user_sema));
      // thread_unblock(p->kernel_thread); // does it automatically schedule them?
    } 
  }
}

// To be called by main thread in process_exit
void free_user_semas(void) {
  struct process* p = thread_current()->pcb;
  while (!list_empty(&(p->user_semas))) {
    struct list_elem *e = list_pop_front(&(p->user_semas));
    struct user_sema_wrapper* sema_wrapper = list_entry(e, struct user_sema_wrapper, elem);
    if (sema_wrapper->kernel_sema != NULL) {
      free(sema_wrapper->kernel_sema);
    }
    free(sema_wrapper);
  }
}

// To be called by main thread in process_exit
void free_user_locks(void) {
  struct process* p = thread_current()->pcb;
  while (!list_empty(&(p->user_locks))) {
    struct list_elem *e = list_pop_front(&(p->user_locks));
    struct user_lock_wrapper* lock_wrapper = list_entry(e, struct user_lock_wrapper, elem);
    if (lock_wrapper->kernel_lock != NULL) {
      free(lock_wrapper->kernel_lock);
    }
    free(lock_wrapper);
  }
} // todo: check if that was called correctly

// Optimization for pthread_join.
struct pthread* get_joinable_pthread(struct thread* t, tid_t tid) {
  struct list *joinable_list = &(t->pcb->joinable_pthreads);
  // size_t size = list_size(pthread_list);
  for (struct list_elem* e = list_begin(joinable_list); e != list_end(joinable_list); e = list_next(e)) {
    struct pthread* p = list_entry(e, struct pthread, joinable_pthread_elem);
    tid_t p_tid = p->tid;
    if (p_tid == tid) {
      return p;
    }
  } 
  return NULL;
}