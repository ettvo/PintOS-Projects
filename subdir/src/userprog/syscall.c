#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"
#include "threads/vaddr.h" 
#include "filesys/directory.h"
// #include "filesys/directory.c"
#include "filesys/filesys.h" // added here
#include "devices/input.h"
#include <stdlib.h>
#include "threads/pte.h"
#include "userprog/pagedir.h" // needed for pointer verification to unmapped things
#include "threads/malloc.h"
// #include "userprog/file-descriptor.h"
#include "lib/float.h"
//Added 
//#include "file-descriptor.h" 
//#include "userprog/process.h"
//#include "threads/vaddr.h"
//#include "lib/kernel/console.c" // putbuf not declared in console.h; should we change console.h ?
// static void sys_open (struct intr_frame *f UNUSED, char* name);
// static void sys_read (struct intr_frame *f UNUSED, int fd, void* buffer, unsigned size);
struct lock global_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&global_lock);
}

  /* printf("System call number: %d\n", args[0]); */
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
  check_valid_ptr((uint32_t*)f->esp + 4); // copypasta

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
    //thread_current() -> pcb -> has_called_exit = true;
    process_exit();
    // actually need to call process exit on all pcb^M
  } 
  // else if (args[0] == SYS_PRACTICE) { // TODO what is practice syscall number?
  //   f->eax = sys_practice(args[1]);
  // }
  
  // Start of File Syscall
  else if (args[0] == SYS_CREATE) {
    // printf("System call number: %d\n", args[0]);
    f->eax = sys_create((void*)args[1], args[2]);
  }
  else if (args[0] == SYS_REMOVE) {
      // printf("System call number: %d\n", args[0]);
      f->eax = sys_remove((void*)args[1]);
  }
  else if (args[0] == SYS_OPEN) {
      // printf("System call number: %d\n", args[0]);
    lock_acquire(&global_lock);
    f->eax = sys_open((void*)args[1]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_FILESIZE) {
      // printf("System call number: %d\n", args[0]);
      lock_acquire(&global_lock);
      f->eax = sys_filesize(args[1]);
      lock_release(&global_lock);
  }
  else if (args[0] == SYS_READ) {
      // printf("System call number: %d\n", args[0]);
    // might slow down too much
    lock_acquire(&global_lock);
    f->eax = sys_read(args[1], (void*)args[2], args[3]);
    lock_release(&global_lock);
    // struct fd* file_desc = find(thread_current()->pcb->fd_table, args[1]);
    // if (file_desc == NULL) {
    //   return -1;
    // }
    // //return (int)file_read(file_desc->file, buffer, (off_t)size);
    // f->eax = file_read(file_desc->file, (void*)args[2], args[3]);
  }
  else if (args[0] == SYS_WRITE) {
      // printf("System call number: %d\n", args[0]);
      // how the hell do I get int fd, const void *buffer, unsigned size using args?
      // args[1] : fd
      // args[2] : buffer
      // args[2] : size unsigned
      //f->eax = sys_write(args[1], (const void*)args[2], args[3]);
    lock_acquire(&global_lock);
    f->eax = sys_write(args[1], (void*)args[2], args[3]);
    lock_release(&global_lock);

      // todo: add exit if f->eax = -1; (or exit from output of sys_write)
      //putbuf((const char*) args[2], (size_t) args[3]);
  }
  else if (args[0] == SYS_SEEK) {
    // printf("System call number: %d\n", args[0]);
    lock_acquire(&global_lock);
    sys_seek(args[1], args[2]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_TELL) {
    // printf("System call number: %d\n", args[0]);^
    lock_acquire(&global_lock);
    f->eax = sys_tell(args[1]);
    lock_release(&global_lock);
  }
  else if (args[0] == SYS_CLOSE) {
    // printf("System call number: %d\n", args[0]);
    lock_acquire(&global_lock);
    sys_close(args[1]);  
    lock_release(&global_lock);
  }
  // Start of process syscalls
  else if (args[0] == SYS_PRACTICE) {
      // printf("System call number: %d\n", args[0]);
      f->eax = sys_practice(args[1]);
      return;
  }
  else if (args[0] == SYS_HALT) {
      // printf("System call number: %d\n", args[0]);
  }
  else if (args[0] == SYS_EXEC) {
    char* cmd_line = (char*)args[1];
    f -> eax = sys_exec(cmd_line);
  }
  else if (args[0] == SYS_WAIT) {
    // printf("System call number: %d\n", args[0]);
    int pid = args[1];
    f -> eax = sys_wait(pid);
  } else if (args[0] == SYS_COMPUTE_E) {
    int n = args[1];
    int e = sys_sum_to_e(n);
    f -> eax = e;
  }
  else if (args[0] == SYS_CHDIR) { // locks? only if changing things
    f->eax = sys_chdir((void*)args[1]);
  }
  else if (args[0] == SYS_MKDIR) {
    f->eax = sys_mkdir((void*)args[1]);
  }
  else if (args[0] == SYS_READDIR) {
    f->eax = sys_readdir(args[1], (void*)args[2]);
  }
  else if (args[0] == SYS_ISDIR) {
    f->eax = sys_isdir(args[1]);
  }
  else if (args[0] == SYS_INUMBER) {
    f->eax = sys_inumber(args[1]);
  }
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
  // cannot remove ., .., or root (i.e. empty string)
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

int sys_open(char* name) { // const
  check_valid_ptr((void *)name);
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  //struct dir* prev_cwd = thread_current()->cwd;
  // does this open directories or just files?
  
  // check if is_dir
  struct fd* fd;
  struct file* file = filesys_open(name);
  if (file == NULL) {
    return -1;
  }
  if (is_file_name(name)) {
    fd = add(fd_table, file, name, false);
  }
  else {
    // dir_entry* lookup_only_parent(char* name)
    fd = add(fd_table, file, get_filename_from_path(name), true);
    //dir_close(dir);
  }
  if (fd == NULL) return -1;
  // // change behavior based on dir or file?
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
  // reads from FD and puts bytes into buffer
  check_valid_ptr(buffer);
  if (fd == 0) {
    uint8_t curr;
    uint8_t* buffer = buffer;
    // size_t total_spaces = sizeof(buffer)/buffer[0]; // todo: use if running to issue involving how big the buffer array is
    for(int total = 0; total < (int)size; total += 1) {
      curr = input_getc();
      buffer[total] = curr;
    }
    return size;
  }
  else if (fd == 1 || fd < 0) {
    // f->eax = -1;
    return -1;
  }
  
  struct fd* file_desc = find(thread_current()->pcb->fd_table, fd);
  if (file_desc == NULL) {
    return -1;
  }
  if (file_desc->is_dir) return -1; // can't read or write on dir
  // int total = file_read(file_desc->file, str, size);
  // int x = total + 0;
  // free(str);
  char* str = (char*)buffer;
  //int x = file_read_at(file_desc->file, str, size, 0);
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
  // return -1;
  // check if a file is open
  // return error
  // write to a file using write_file in "filesys/file.h"
  // return the number of bytes actually written (which is returned from write_file) 
  
  // commented out due to change to being inside a function and not in the syscall handler
  //int fd = args[1];
  //const void *buffer = (const void*) args[2];
  //unsigned size = args[3];
  check_valid_ptr(buffer);
  if(fd == 1) { // stdout case
    putbuf((const char*) buffer, (size_t) size);
    // for (int total = 0; size - total > 0; total += 100) {
    //   if (size - total > 100) {
    //     putbuf((const char*) buffer, (size_t) (100));  
    //   }
    //   else {
    //     putbuf((const char*) buffer, (size_t) (size - total)); 
    //   } 
    // }
    return size; // size?
  } 
  else if (fd == 0) {
    return -1;
  }
  else { 
    // get file and fd_table. You can find it in process.h and file.h
    struct fd_table *fd_table = thread_current()->pcb->fd_table;
    struct fd* file_desc = find(fd_table, fd);
    if (file_desc == NULL) {
      // f->eax = -1;
      // need to exit kernel
      return -1;
    }
    if (file_desc->is_dir) return -1; // can't read or write on directory
    struct file *file = get_file_pointer(fd_table, fd);

    // check if file is open (maybe function in file-descriptor.c) return -1 if not

    if (!can_write_to_file(file)) { // justice for matthew
      // f->eax = -1;
      // need to exit kernel
      return -1; // change
    }

    int bytes_written = file_write(file, buffer, (off_t) size);
    // f -> eax = bytes_written;
    return bytes_written;
  }
}

//   if (can_write_to_file(file)) { // justice for matthew
//     f->eax = -1;
//     // need to exit kernel
//     return;
//   }
//   int bytes_written = file_write(file, buffer, (off_t) size);
//   f -> eax = bytes_written;
// }


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
  return (unsigned)file_tell(file_desc->file); // todo: need to check for int overflow w/ off_t cast to unsigned
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
    // return -1;
    return;
  }
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_desc = find(fd_table, fd);
  if (file_desc == NULL) {
    // return -1;
    return;
    //sys_exit(-1); // 
  }
  // close file
  file_close(file_desc->file);
  // if (file_desc->is_dir) {
  //   dir_close(file_desc->file);
  // }
  // else {
  //   file_close(file_desc->file);
  // }
  int removal_status = remove(fd_table, fd);
  if (removal_status != 0) {
    // return -1;
    //sys_exit(-1);
    return;
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
// void sys_halt(void) {
//   return;
// }


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
  //f->eax = status;
  printf("%s: exit(%d)", thread_current()->pcb->process_name, status);
  //return;
  // free the pcb here ? or in process_exit
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
// pid_t sys_exec(const char* cmd_line) {
// int sys_exec(const char* cmd_line) {
//   return (int)cmd_line;
// }
pid_t sys_exec(char* cmd_line) { // const
  check_valid_ptr((void *) cmd_line);
  check_valid_ptr((void *) cmd_line + 16);

  pid_t pid = process_execute(cmd_line);
  // block until load is complete
  // sema_down(&thread_current()->pcb->shared_data->child_load_sema);
  
  /* Add the child process's shared_data to list of parent process's children processes */

  //add_child(pid);

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
  // struct process *pcb = thread_current() -> pcb;
  // struct list *children = &(pcb -> children);

  // struct shared_data *child_data = find_shared_data(children, pid); // change; error starts here 
  // if (!child_data) return -1;

  // // Checks if parent has called wait on the child before
  // if (child_data -> waited_on) return -1;
  // child_data -> waited_on = true;

  // // if reference count is 1, then child has exited
  // if (child_data -> ref_count <= 1) {
  //   return child_data -> exit_code;
  // }

  // sema_down(&(child_data -> wait_sema));
  // int exit_status = child_data -> exit_code;

  // return exit_status;
  return process_wait(pid);
}


// refer to file.c instead from filesys/// write from buffer to corresponding file pointed by file descriptor
// synchronization is not assumed in this code thus it has to be wrapped by mutex or semaphore
// int write_from_buffer(int fd, const *buffer, unsigned size) {
//     // initialize buffer start
//     // initialize buffer end
//     // initialize read_buffer_count
//     int read_count;
//     if(fd == 1) {

//     } else {
//         read_count = file_write(fd, buffer, size);
//     }
//     // while read_buffer_count < size:
//     //    write_to_file() <- there's gotta be a helper function that exists already : Im looking for an existing helper function rn
//     //    update start, update end
//     //    update read_buffer_count
//     //    check you can still write ex) any error
    
//     // return read_buffer_count
//     return read_count;
// //}

/*
  else if (args[0] == SYS_SEEK) {
      // printf("System call number: %d\n", args[0]);
  }
  else if (args[0] == SYS_TELL) {
      // printf("System call number: %d\n", args[0]);
  }
  else if (args[0] == SYS_CLOSE) {
      // printf("System call number: %d\n", args[0]);
  }
*/
  

/* Changes the current working directory of the process to dir, which may be relative or absolute. 
Returns true if successful, false on failure. 
*/
bool sys_chdir(char* dir) {
  check_valid_ptr((void *) dir);
  struct dir* curr = get_dir_from_path(dir);
  if (curr == NULL) return false;
  thread_current()->pcb->cwd = curr; // does it change the CWD of the given thread too?
  dir_close(curr);
  return true;
}

/* Creates the directory named dir, which may be relative or absolute. Returns true if successful, false on failure. 
Fails if dir already exists or if any directory name in dir, besides the last, does not already exist. 
That is, mkdir("/a/b/c") succeeds only if /a/b already exists and /a/b/c does not.
*/
bool sys_mkdir(char* dir) {
  check_valid_ptr((void *) dir);
  if (dir == NULL || strlen(dir) == 0) return false; 

  // verify dir (abs or rel)
  // make dir in given path

  // // get dir but remove the last / with the find occurrence thing
  // char* file = get_filename_from_path(dir); // finds the last entry (the new directory name);
  block_sector_t block = 0;
  if (is_path(dir)) {
    struct dir_entry* curr_entry;
    curr_entry = lookup_only_parent(dir);
    if (curr_entry == NULL) return false; // indicates that a directory in the path DNE
    free_map_allocate(1, &block);
    // struct dir* parent = get_dir_from_entry(curr);
    bool success = dir_create(block, 16);
    struct dir* curr = get_dir_from_entry(curr_entry);
    success = success && dir_add(get_dir_from_entry(curr_entry), get_filename_from_path(dir), block);
    dir_close(curr);
    return curr;
  }
  else {
    struct dir* curr = thread_current()->pcb->cwd;
    if (curr == NULL) {
      curr = dir_open_root();
    }
    else {
      curr = dir_reopen(thread_current()->pcb->cwd);
    }
    free_map_allocate(1, &block);
    bool success = dir_create(block, 16);
    success = success && dir_add(curr, dir, block);
    dir_close(curr);
    return success;
  }
  // check if dir exists in CWD
  // sector number can be gotten from dir_entry

  
  
  // add to parent directory
  // todo, check that given dir_entry is a dir
  // set created directory to have a parent
  // filesys_create?

  //return dir_add(get_dir_from_entry(curr), file, curr->inode_sector); // returns false if already exists in CWD; assuming adding to given directory
  // todo: move everything from this func into a different one in directory.c to avoid compile errors + uncomment above line
  // create dir
  // That is, mkdir("/a/b/c") succeeds only if /a/b already exists and /a/b/c does not.
}


/* Reads a directory entry from file descriptor fd, which must represent a directory. If successful, stores the null-terminated file name in name, which must have room for READDIR_MAX_LEN + 1 bytes, and returns true. If no entries are left in the directory, returns false.
. and .. should not be returned by readdir
If the directory changes while it is open, then it is acceptable for some entries not to be read at all or to be read multiple times. Otherwise, each directory entry should be read once, in any order.
READDIR_MAX_LEN is defined in lib/user/syscall.h. If your file system supports longer file names than the basic file system, you should increase this value from the default of 14.
*/
bool sys_readdir(int fd, char* name) {
  check_valid_ptr((void *) name); // need to check that it is still valid READDIR_MAX_LEN + 1 bytes later

  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_desc = find(fd_table, fd);
  if (file_desc == NULL || !file_desc->is_dir) {
    return false;
  }
  strlcpy(name, file_desc->file_name, strlen(file_desc->file_name) + 1);
  // check if FD corresponds to a directory
  // check if NAME has enough size to store the name
  // reads through ALL the names
  return true;
}

/* Returns true if fd represents a directory, false if it represents an ordinary file. */
bool sys_isdir(int fd) {
  struct fd* file_desc = find(thread_current()->pcb->fd_table, fd);
  if (file_desc == NULL) {
    return false;
  }
  return file_desc->is_dir;
  // need to double check logic for updating FD is_dir
}


/*
Returns the inode number of the inode associated with fd, which may represent an ordinary file or a directory.
An inode number persistently identifies a file or directory. It is unique during the file’s existence. In Pintos, the sector number of the inode is suitable for use as an inode number.
We have provided the ls and mkdir user programs, which are straightforward once the above syscalls are implemented. We have also provided pwd, which is not so straightforward. The shell program implements cd internally.
The pintos extract and pintos append commands should now accept full path names, assuming that the directories used in the paths have already been created. This should not require any significant extra effort on your part.
*/
int sys_inumber(int fd) {
  struct fd* file_desc = find(thread_current()->pcb->fd_table, fd);
  if (file_desc == NULL) {
    return -1;
  }
  // return file_desc->file->inode->sector; // assumes the inode number is the sector number
  // inumber not yet set up?
  return -1;
}