#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"
#include "threads/vaddr.h" 

#include "filesys/filesys.h"
#include "devices/input.h"
#include <stdlib.h>
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "lib/float.h"
struct lock global_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&global_lock);
}

/* Check to see if ptr is outside of user memory. If so, exit*/
void check_valid_ptr(void *ptr) {
  struct thread* cur = thread_current();
  if (ptr == NULL || (uint32_t)ptr == 0 || is_kernel_vaddr(ptr) || is_kernel_vaddr(ptr + 1)) {
    printf("%s: exit(%d)\n", cur->pcb->process_name, -1);
    process_exit();
  }
  uint32_t* pd = cur->pcb->pagedir;
  void* page = pagedir_get_page(pd, ptr);
  if (page == NULL) { 
    printf("%s: exit(%d)\n", cur->pcb->process_name, -1);
    process_exit();
  }
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */


  check_valid_ptr(f->esp);
  check_valid_ptr((uint32_t*)f->esp + 1);
  check_valid_ptr((uint32_t*)f->esp + 2);
  check_valid_ptr((uint32_t*)f->esp + 3);
  check_valid_ptr((uint32_t*)f->esp + 4);

  /* Syscalls can take a maximum of 4 arguments, each of size 4 bytes (lib/usr/syscall.c)
     To be safe, we should terminate the program if f->esp is close enough to PHYS_BASE that
     the arguments to a syscall might reach into user memory*/
  int max_syscall_arg_size = 16; // 4 args, 4 bytes each
  if (max_syscall_arg_size + (uint32_t) f->esp > (uint32_t)PHYS_BASE) {
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();
  }


  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    thread_current() -> pcb -> shared_data -> exit_code = args[1];
    process_exit();
  } 
  
  /* Start of File Syscall */
  else if (args[0] == SYS_CREATE) {
    // printf("System call number: %d\n", args[0]);
    lock_acquire(&global_lock);
    f->eax = sys_create((void*)args[1], args[2]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_REMOVE) {
      // printf("System call number: %d\n", args[0]);
      lock_acquire(&global_lock);
      f->eax = sys_remove((void*)args[1]);
      lock_release(&global_lock);
  }
  else if (args[0] == SYS_OPEN) {
    lock_acquire(&global_lock);
    f->eax = sys_open((void*)args[1]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_FILESIZE) {
      lock_acquire(&global_lock);
      f->eax = sys_filesize(args[1]);
      lock_release(&global_lock);
  }
  else if (args[0] == SYS_READ) {
    lock_acquire(&global_lock);
    f->eax = sys_read(args[1], (void*)args[2], args[3]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_WRITE) {
    lock_acquire(&global_lock);
    f->eax = sys_write(args[1], (void*)args[2], args[3]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_SEEK) {
    lock_acquire(&global_lock);
    sys_seek(args[1], args[2]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_TELL) {
    lock_acquire(&global_lock);
    f->eax = sys_tell(args[1]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_CLOSE) {
    lock_acquire(&global_lock);
    sys_close(args[1]);  
    lock_release(&global_lock);
  }
  // Start of process syscalls
  else if (args[0] == SYS_PRACTICE) {
      f->eax = sys_practice(args[1]);
      return;
  }
  else if (args[0] == SYS_HALT) {
      // printf("System call number: %d\n", args[0]);
      sys_halt();
  }
  else if (args[0] == SYS_EXEC) {
    char* cmd_line = (char*)args[1];
    f -> eax = sys_exec(cmd_line);
  }
  else if (args[0] == SYS_WAIT) {
    int pid = args[1];
    f -> eax = sys_wait(pid);
  } else if (args[0] == SYS_COMPUTE_E) {
    int n = args[1];
    int e = sys_sum_to_e(n);
    f -> eax = e;
  } else if(args[0] == SYS_PT_CREATE) {
    //lock_acquire(&global_lock);
    f->eax = sys_pthread_create((stub_fun)args[1], (pthread_fun)args[2], (uint32_t)args[3]);
    //lock_release(&global_lock);
  }
  else if (args[0] == SYS_PT_JOIN) {
    int tid = args[1];
    f -> eax = sys_pthread_join(tid);
  }
  else if (args[0] == SYS_PT_EXIT) {
    sys_pthread_exit();
  }
  else if (args[0] == SYS_GET_TID) {
    f->eax = thread_current()->tid;
  }

  // FOR USERTHREADS

  else if (args[0] == SYS_LOCK_INIT) {
    bool success = sys_lock_init(args[1]);
    f->eax = (int) success;
  } 
  else if (args[0] == SYS_LOCK_ACQUIRE) {
    bool success = sys_lock_acquire(args[1]);
    f->eax = (int) success;
  } 
  else if (args[0] == SYS_LOCK_RELEASE) {
    bool success = sys_lock_release(args[1]);
    f->eax = (int) success;
  } 
  else if (args[0] == SYS_SEMA_INIT) {
    bool success = sys_sema_init(args[1], args[2]);
    f->eax = (int) success;
  } 
  else if (args[0] == SYS_SEMA_DOWN) {
    bool success = sys_sema_down(args[1]);
    f->eax = (int) success;
  }
  else if (args[0] == SYS_SEMA_UP) {
    bool success = sys_sema_up(args[1]);
    f->eax = (int) success;
  }
  
  // SYS_PT_EXIT,      /* Exits the current thread */
  // SYS_PT_JOIN,      /* Waits for thread to finish */
  // SYS_LOCK_INIT,    /* Initializes a lock */
  // SYS_LOCK_ACQUIRE, /* Acquires a lock */
  // SYS_LOCK_RELEASE, /* Releases a lock */
  // SYS_SEMA_INIT,    /* Initializes a semaphore */
  // SYS_SEMA_DOWN,    /* Downs a semaphore */
  // SYS_SEMA_UP,      /* Ups a semaphore */

  return;
}


/* 
Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. 
Creating a new file does not open it: opening the new file is 
  a separate operation which would require an open system call.
*/
bool sys_create(char* file, unsigned initial_size) {
    check_valid_ptr((void *) file);
    return filesys_create(file, (off_t)initial_size);
}


/*
Deletes the file named file. 
Returns true if successful, false otherwise.
A file may be removed regardless of whether it is open or closed, 
  and removing an open file does not close it. 
*/
bool sys_remove(char* file) {
  check_valid_ptr((void *) file);  
  return filesys_remove(file);
}


/*
Opens the file named file. 
Returns a nonnegative integer handle called a “file descriptor” (fd), 
  or -1 if the file could not be opened.

File descriptors numbered 0 and 1 are reserved for the console: 
  0 (STDIN_FILENO) is standard input and 1 (STDOUT_FILENO) is 
  standard output. 
  open should never return either of these file descriptors.

Each process has an independent set of file descriptors.
When a single file is opened more than once, whether 
  by a single process or different processes, 
  each open returns a new file descriptor. 
  Different file descriptors for a single file 
  are closed independently in separate calls to 
  close and they do not share a file position.
*/

int sys_open(char* name) {
  check_valid_ptr((void *)name);
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct file* file = filesys_open(name);
  if (file == NULL) {
    return -1;
  }
  struct fd* fd = add(fd_table, file);
  return fd->val;
}


/* 
Returns the size, in bytes, of the open file with file descriptor fd. 
Returns -1 if fd does not correspond to an entry in the file 
  descriptor table.
*/
int sys_filesize(int fd) {
  struct fd* file_desc = find(thread_current()->pcb->fd_table, fd);
  if (file_desc == NULL) {
    return -1;
  }
  return (int)file_length(file_desc->file);
}

/* 
Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other 
than end of file, such as fd not corresponding to an entry in 
the file descriptor table). STDIN_FILENO reads from the keyboard 
using the input_getc function in devices/input.c.
*/
int sys_read(int fd, void* buffer, unsigned size) {
  check_valid_ptr(buffer);
  if (fd == 0) {
    uint8_t curr;
    uint8_t* buffer = buffer;
    for(int total = 0; total < (int)size; total += 1) {
      curr = input_getc();
      buffer[total] = curr;
    }
    return size;
  }
  else if (fd == 1 || fd < 0) {
    return -1;
  }
  
  struct fd* file_desc = find(thread_current()->pcb->fd_table, fd);
  if (file_desc == NULL) {
    return -1;
  }

  char* str = (char*)buffer;
  int y = file_read(file_desc->file, str, size);
  return y;

}


/* 
Writes size bytes from buffer to the open file with 
  file descriptor fd. 
Returns the number of bytes actually written, which may be less 
  than size if some bytes could not be written. 
  Returns -1 if fd does not correspond to an entry in the 
  file descriptor table.
File descriptor 1 writes to the console. 
  Your code to write to the console should write all of buffer 
  in one call to the putbuf function lib/kernel/console.c, 
  at least as long as size is not bigger than a few hundred bytes and 
  should break up larger buffers in the process.
*/
int sys_write(int fd, void* buffer, unsigned size) {
  check_valid_ptr(buffer);
  if(fd == 1) {
    putbuf((const char*) buffer, (size_t) size);
    return size;
  } 
  else if (fd == 0) {
    return -1;
  }
  else { 
    struct fd_table *fd_table = thread_current()->pcb->fd_table;
    struct fd* file_desc = find(fd_table, fd);
    if (file_desc == NULL) {
      return -1;
    }

    struct file *file = get_file_pointer(fd_table, fd);

    if (!can_write_to_file(file)) {
      return -1;
    }

    int bytes_written = file_write(file, buffer, (off_t) size);
    return bytes_written;
  }
}

/* 
Changes the next byte to be read or written in open file fd to 
  position, expressed in bytes from the beginning of the file. 
  Thus, a position of 0 is the file’s start. In other words,
  this changes the offset associated with the fd.
If fd does not correspond to an entry in the file descriptor 
  table, this function should do nothing.
*/
void sys_seek(int fd, unsigned position) {
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_desc = find(fd_table, fd);
  if (file_desc != NULL) {
    file_seek(file_desc->file, (off_t)position);
  }
}


/* 
Returns the position of the next byte to be read or written in 
  open file fd, expressed in bytes from the beginning of the file. 
  If the operation is unsuccessful, it can either exit with -1 or 
  it can just fail silently.
*/
unsigned sys_tell(int fd) {
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_desc = find(fd_table, fd);
  if (file_desc == NULL) {
    sys_exit(-1);
  }
  return (unsigned)file_tell(file_desc->file);
}



/* 
Closes file descriptor fd. Exiting or terminating a process must 
  implicitly close all its open file descriptors, as if by 
  calling this function for each one. 
If the operation is unsuccessful, it can either exit with -1 
  or it can just fail silently.
*/
void sys_close(int fd) {
  if (fd < 2) {
    return -1;
  }
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_desc = find(fd_table, fd);
  if (file_desc == NULL) {
    return -1;
  }
  file_close(file_desc->file);
  int removal_status = remove(fd_table, fd);
  if (removal_status != 0) {
    return -1;
  }
}


/* 
A “fake” syscall designed to get you familiar with the syscall 
interface This syscall increments the passed in integer argument 
by 1 and returns it to the user.
*/
int sys_practice(int i) {
  return i + 1;
}


/* 
Terminates Pintos by calling the shutdown_power_off 
  function in devices/shutdown.h. This should be seldom used, 
  because you lose some information about possible deadlock 
  situations, etc.
*/
void sys_halt(void) {
  shutdown_power_off();
}


/* 
Terminates the current user program, returning status to the kernel. 
If the process’s parent waits for it (see below), this is the status 
  that will be returned. 
  Conventionally, a status of 0 indicates success and nonzero values 
  indicate errors. Every user program that finishes in normally calls 
  exit – even a program that returns from main calls exit indirectly 
  (see Program Startup). 
  
In order to make the test suite pass, you need to print out the 
  exit status of each user program when it exits. The format 
  should be %s: exit(%d) followed by a newline, where the process 
  name and exit code respectively subsitute %s and %d.
*/
void sys_exit(int status) {
  printf("%s: exit(%d)", thread_current()->pcb->process_name, status);
  process_exit();
}


/* 
Runs the executable whose name is given in cmd_line, passing any 
  given arguments, and returns the new process’s program id (pid). 
  If the program cannot load or run for any reason, return -1. 
  Thus, the parent process cannot return from a call to exec until 
  it knows whether the child process successfully loaded its 
  executable. You must use appropriate synchronization to ensure 
  this.
*/

pid_t sys_exec(char* cmd_line) { // const
  check_valid_ptr((void *) cmd_line);
  check_valid_ptr((void *) cmd_line + 16);

  pid_t pid = process_execute(cmd_line);
  return pid;
}



/* 
Waits for a child process pid and retrieves the child’s exit status. 
If pid is still alive, waits until it terminates. Then, returns the 
  status that pid passed to exit. 
  It is perfectly legal for a parent process to wait for 
  child processes that have already terminated by the time the 
  parent calls wait, but the kernel must still allow the parent to 
  retrieve its child’s exit status, or learn that the child was 
  terminated by the kernel.

wait must fail and return -1 immediately if any of the 
  following conditions are true:
    1) pid does not refer to a direct child of the calling process.
    2) The process that calls wait has already called wait on pid. 
      That is, a process may wait for any given child at most once.
    3) If pid did not call exit but was terminated by the kernel 
      (e.g. killed due to an exception), wait must return -1. 
*/

int sys_wait(pid_t pid) {
  return process_wait(pid);
}
  

/* 
Creates a new user thread running stub function sfun, with arguments tfun and arg. 
Returns TID of created thread, or TID_ERROR if allocation failed. 
*/
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
  // check_valid_ptr(arg);
  // check_valid_ptr(sfun); // might not be in userspace?
  // check_valid_ptr(tfun);
  // // a pthread is a kernel thread in a trench coat --> switch between user and kernel mode with is_trap_from_userspace
  tid_t tid = pthread_execute(sfun, tfun, arg);
  return tid;
}

tid_t sys_pthread_join(tid_t tid) { 
  tid_t ret = pthread_join(tid);
  // struct pthread* p = find_pthread(thread_current(), tid);
  // if (p != NULL && ret != TID_ERROR) sema_down(&(p -> user_sema));
  // if (p != NULL && ret != TID_ERROR) sema_up(&(p -> user_sema));
  return ret;
}

void sys_pthread_exit(void) {
  struct thread* curr = thread_current();
  if (curr == curr->pcb->main_thread) {
    pthread_exit_main();
  }
  else {
    pthread_exit();
  }
}
  // NO_RETURN;

// FOR USERTHREADS

bool sys_lock_init(void *lock) {
  if (lock == NULL) return false;

  check_valid_ptr(lock);

  struct lock *kernel_lock = malloc(sizeof(struct lock));
  struct user_lock_wrapper *wrapper = malloc(sizeof(struct user_lock_wrapper));
  /* If either malloc fails, the lock initialization fails */
  if (!(kernel_lock && wrapper)) {
    if (!kernel_lock) free(wrapper);
    if(!wrapper) free(kernel_lock);
    return false;
  }

  lock_init(kernel_lock);
  wrapper -> has_been_acquired = false;
  wrapper -> user_lock = lock;
  wrapper -> kernel_lock = kernel_lock;

  list_push_front(&thread_current()->pcb->user_locks, &wrapper->elem);
  return true;
}

bool sys_lock_acquire(void *lock) {
  if (lock == NULL) return false;

  check_valid_ptr(lock);

  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->pcb->user_locks); e != list_end (&t->pcb->user_locks); e = list_next(e))
  {
    struct user_lock_wrapper *wrapper = list_entry (e, struct user_lock_wrapper, elem);
    if (wrapper->user_lock == lock) {
      if (wrapper->has_been_acquired)
        return false;
      lock_acquire(wrapper->kernel_lock);
      wrapper->has_been_acquired = true;
      return true;
    }
  }
  return false; // todo: check condition if it can occur
}

bool sys_lock_release(void *lock) {
  if (lock == NULL) return false;

  check_valid_ptr(lock);

  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->pcb->user_locks); e != list_end (&t->pcb->user_locks); e = list_next(e))
  {
    struct user_lock_wrapper *wrapper = list_entry (e, struct user_lock_wrapper, elem);
    
    if (wrapper->user_lock == lock) {
      if (wrapper->kernel_lock->holder == thread_current()) {
        lock_release(wrapper->kernel_lock);
        wrapper->has_been_acquired = false;
        return true;
      }
        

      // free(wrapper->kernel_lock);
      // list_remove(&wrapper->elem); // remove from list of locks for a given process but not from all locks list
      // free(wrapper);
    }
  }
  return false;
}

bool sys_sema_init(void *sema, int val) {
  if (sema == NULL) return false;
  if (val < 0) return false;

  check_valid_ptr(sema);

  struct semaphore *kernel_sema = malloc(sizeof(struct semaphore));
  struct user_sema_wrapper *wrapper = malloc(sizeof(struct user_sema_wrapper));
  /* If either malloc fails, the lock initialization fails */
  if (!(kernel_sema && wrapper)) {
    if (kernel_sema != NULL) free(kernel_sema);
    if (wrapper != NULL) free(wrapper);
    return false;
  }

  sema_init(kernel_sema, val);
  wrapper -> user_sema = sema;
  wrapper -> kernel_sema = kernel_sema;

  list_push_front(&thread_current()->pcb->user_semas, &wrapper->elem);
  return true;
}

bool sys_sema_down(void *sema) {
  if (sema == NULL) return false;

  check_valid_ptr(sema);

  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->pcb->user_semas); e != list_end (&t->pcb->user_semas); e = list_next(e))
  {
    struct user_sema_wrapper *wrapper = list_entry (e, struct user_sema_wrapper, elem);
    if (wrapper->user_sema == sema) {
      sema_down(wrapper->kernel_sema);
      return true;
    }
  }
  return false;
}

bool sys_sema_up(void *sema) {
  if (sema == NULL) return false;

  check_valid_ptr(sema);

  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->pcb->user_semas); e != list_end (&t->pcb->user_semas); e = list_next(e))
  {
    struct user_sema_wrapper *wrapper = list_entry (e, struct user_sema_wrapper, elem);
    
    if (wrapper->user_sema == sema) {
      sema_up(wrapper->kernel_sema);

      //free(wrapper->kernel_sema);
      //list_remove(&wrapper->elem);
      //free(wrapper);

      return true;
    }
  }
  return false;
}
