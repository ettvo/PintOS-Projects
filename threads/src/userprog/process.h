#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

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

  struct list children;
  struct semaphore list_sema;  
  struct shared_data* shared_data;
  bool has_exec;
  struct file* cur_file;
  struct list pthread_list; // For pThreads

  // FOR USERTHREADS
  /* For user-level locks and semaphores */
  struct list user_locks;    /* List of struct user_lock_wrappers (synch.h) */
  struct list user_semas;    /* List of struct user_sema_wrappers (synch.h) */

  // struct list join_pthreads; /* List of pthreads that joined on the main thread. */
  struct semaphore pthread_exit_sema; // Used when process_exit is called without calling pthread_exit_main
  struct list joinable_pthreads;
};

struct shared_data {
  bool load; /* Indicate child process is successfully loaded*/
  struct semaphore wait_sema; /* Signal loading is completed whether it succeed or failed*/
  pid_t pid; /* my pid */
  struct list_elem elem; /* make it iterable*/
  int ref_count; /* set it free only when it is 0 i.e. no lost child!*/

  int exit_code; /* meta data to hold exit status even after process/thread is gone*/
  bool waited_on;
};

struct pthread {
  struct list_elem pthread_elem; // for pthread_list
  struct list_elem joinable_pthread_elem; // 
  uint8_t* user_stack;
  struct thread* kernel_thread; 
  struct semaphore user_sema; // used in joins
  // use exit code in pcb after joins or termination
  bool has_joined;  // pthread_join should fail if called on a thread that has already                     
                    // been joined on
  bool terminated; // when thread_exit has been called without join happening first
  tid_t tid;
  struct thread* waiting_on; // used in joins
  struct thread* main_thread; // used in joins when pthread is terminated but process not exited
};

/* project 1 process helper*/
void init_shared_data(struct shared_data* shared_data);
/* end of helper*/

/* Find the shared data struct of a (child) process */
struct shared_data* find_shared_data(struct list *children, int pid);


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

struct fd_table {
  struct list fds;
  int next_unused_fd;
};

struct fd {
    struct list_elem list_fd;
    int val; 
    struct file* file; 
};

struct fd* find(struct fd_table *table, int fd);
int remove(struct fd_table *table, int fd);
struct fd* add(struct fd_table *table, struct file* file);
void init_table(struct fd_table* table);
struct file* get_file_pointer(struct fd_table* fd_table, int fd);
void free_table(struct fd_table *fd_table);


bool setup_thread(void (**eip)(void), void** esp, struct pthread* curr, void* sfun);

struct pthread* find_pthread(struct thread* t, tid_t tid);
void signal_pthread_death(void);
void wake_up_pthreads_joined_on_main(void);
void wake_up_pthread_waiters(void);

void free_user_semas(void);
void free_user_locks(void);
struct pthread* get_joinable_pthread(struct thread* t, tid_t tid);

#endif /* userprog/process.h */
