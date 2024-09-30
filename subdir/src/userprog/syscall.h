#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

//#include "file-descriptor.h" // added starting here
#include "userprog/process.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void check_valid_ptr(void *ptr);
void syscall_init(void);

// Start of file operations syscalls
// changed from removed const qualifiers to allow for typecasting; C allows for casting only non const -> const; see project spec for specifications
bool sys_create(char* file, unsigned initial_size); // const
bool sys_remove(char* file); // const
// void sys_open(struct intr_frame* f UNUSED, char* name);
int sys_open(char* name);
int sys_filesize(int fd);
int sys_read(int fd, void* buffer, unsigned size); // const
// int sys_read(int fd, void* buffer, unsigned size); // const
int sys_write(int fd, void* buffer, unsigned size); // const
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

// Start of process syscalls
int sys_practice(int i);
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(char* cmd_line); // const // change
// int sys_wait(pid_t pid);
// int sys_exec(const char* cmd_line);
int sys_wait(int pid); // change




bool sys_chdir(char* dir);
bool sys_mkdir(char* dir);
bool sys_readdir(int fd, char* name);
bool sys_isdir(int fd);
int sys_inumber(int fd);


#endif /* userprog/syscall.h */