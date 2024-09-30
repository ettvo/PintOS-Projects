#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
  unsigned value;      /* Current value. */
  struct list waiters; /* List of waiting threads. */

  struct thread *holder; /* Thread that currently holds the sema. Project 2 */
  struct list_elem elem; /* Used in priority donation. Project 2 */
};

void sema_init(struct semaphore*, unsigned value);
void sema_down(struct semaphore*); 
bool sema_try_down(struct semaphore*);
void sema_up(struct semaphore*); 
void sema_self_test(void);
/* donate_all_priority implements priority donation. 
 This argument should be NULL in non lock operations */
// void priority_sema_down(struct semaphore*, void (*donate_all_priority) (void));
// void priority_sema_up(struct semaphore*, void (*donate_all_priority) (void));


/* Lock. */
struct lock {
  struct thread* holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};

// FOR USERTHREADS
/* Maintains 1 to 1 mapping between user and kernel locks */
struct user_lock_wrapper {
  bool has_been_acquired;  
  void *user_lock;            /* User locks are chars typedef-ed as lock_t in syscall.h */
  struct lock *kernel_lock;   /* Corresponding kernel lock */
  struct list_elem elem;      /* Part of struct list user_locks */
};

// FOR USERTHREADS
/* Maintains 1 to 1 mapping between user and kernel semaphores */
struct user_sema_wrapper {
  void *user_sema;               /* User semaphores are chars typedef-ed as sema_t in syscall.h */
  struct semaphore *kernel_sema; /* Corresponding kernel semaphore */
  struct list_elem elem;         /* Part of struct list user_semas */
};

void lock_init(struct lock*);
void lock_acquire(struct lock*);
bool lock_try_acquire(struct lock*);
void lock_release(struct lock*);
bool lock_held_by_current_thread(const struct lock*);
void release_all_locks_held(struct thread* curr);

/* Priority donation. Project 2 */
void donate_priority(struct semaphore *lock_sema); // Donate priority thread holding lock_sema
void update_priority(struct list *locks_held);     // Get the maximum priority of waiting threads

/* Condition variable. */
struct condition {
  struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition*);
void cond_wait(struct condition*, struct lock*);
void cond_signal(struct condition*, struct lock*);
void cond_broadcast(struct condition*, struct lock*);

/* Readers-writers lock. */
#define RW_READER 1
#define RW_WRITER 0

struct rw_lock {
  struct lock lock;
  struct condition read, write;
  int AR, WR, AW, WW;
};

void rw_lock_init(struct rw_lock*);
void rw_lock_acquire(struct rw_lock*, bool reader);
void rw_lock_release(struct rw_lock*, bool reader);


/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

#endif /* threads/synch.h */

