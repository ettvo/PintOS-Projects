#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void check_valid_ptr(void *ptr);
void syscall_init(void);
bool sys_create(char* file, unsigned initial_size);
bool sys_remove(char* file);
int sys_open(char* name);
int sys_filesize(int fd);
int sys_read(int fd, void* buffer, unsigned size);
int sys_write(int fd, void* buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_practice(int i);
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(char* cmd_line);
int sys_wait(int pid);


// Threads syscalls
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
tid_t sys_pthread_join(tid_t tid);
void sys_pthread_exit(void) NO_RETURN;

// User synchs syscalls
bool sys_lock_init(void* lock);
bool sys_lock_acquire(void* lock); // Should be a bool return val
bool sys_lock_release(void* lock); // Should be a bool return val
bool sys_sema_init(void* sema, int val);
bool sys_sema_down(void* sema); // Should be a bool return val
bool sys_sema_up(void* sema);   // Should be a bool return val
tid_t get_tid(void);

#endif /* userprog/syscall.h */