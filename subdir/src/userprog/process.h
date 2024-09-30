#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
// #include "userprog/file-descriptor.h" // added 

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  struct fd_table* fd_table; /* Pointer to the FD table. */

  struct list children; /* List of children's shared_data */
  struct semaphore list_sema;  
  struct shared_data* shared_data;
  bool has_exec;
  struct file* cur_file;
  struct dir* cwd; 
  //bool has_called_exit = false;
};

// parent process list - visibilty to sharea data's of its own child
// as a process itself - will have a pointer to its own shared data

 // shared data will be access by its own process and parent process using children list
struct shared_data {
  bool load; /* Indicate child process is successfully loaded*/
  struct semaphore wait_sema; /* Signal loading is completed whether it succeed or failed*/
  //struct semaphore wait_sema;
  pid_t pid; /* my pid */
  struct list_elem elem; /* make it iterable*/
  int ref_count; /* set it free only when it is 0 i.e. no lost child!*/

  int exit_code; /* meta data to hold exit status even after process/thread is gone*/
  bool waited_on;
};

/* project 1 process helper*/
void init_shared_data(struct shared_data* shared_data);
/* end of helper*/

/* Find the shared data struct of a (child) process */

struct shared_data* find_shared_data(struct list *children, int pid);
// void add_child(int child_pid);
//struct process *find_process(int pid);


void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);
//struct process *find_process(int pid);



/// File descriptor

struct fd_table {
  struct list fds;
  int next_unused_fd;
};

struct fd {
  struct list_elem list_fd;
  int val; 
  //void* file; // struct file* file or struct dir* dir depending on is_dir
  struct file* file;
  struct dir* dir;
  bool is_dir;
  char* file_name;
};

struct fd* find(struct fd_table *table, int fd);
int remove(struct fd_table *table, int fd); // -1 on failure, 0 on success
struct fd* add(struct fd_table *table, struct file* file, char* file_name, bool is_dir);
void init_table(struct fd_table* table);
struct file* get_file_pointer(struct fd_table* fd_table, int fd);

void free_table(struct fd_table *fd_table); // ADDED


#endif /* userprog/process.h */
