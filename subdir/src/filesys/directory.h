#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/off_t.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */

  struct dir* parent; /* Parent directory. */
  // struct list children; /* Refers to directory children (not directory entries). */
  // struct list_elem elem; /* Used to add to list of parent directory's children. */
  // TODO: init children in directory creation, add children to parent's list in making dir
  // resolve lookup with lookup() and check if the file is a directory or file
};

/* A single directory entry. Refers to a file that can be either a directory or a normal file. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  int entry_count;
};

struct inode;
// moving to directory.c
// struct dir* ROOT_DIR; // non-NULL after userprog_init called

/* Opening and closing directories. */
bool dir_create(block_sector_t sector, size_t entry_cnt);
struct dir* dir_open(struct inode*);
struct dir* dir_open_root(void);
struct dir* dir_reopen(struct dir*);
void dir_close(struct dir*);
struct inode* dir_get_inode(struct dir*);

/* Reading and writing. */
bool dir_lookup(const struct dir*, const char* name, struct inode**);
bool dir_add(struct dir*, const char* name, block_sector_t);
bool dir_remove(struct dir*, const char* name);
bool dir_readdir(struct dir*, char name[NAME_MAX + 1]);

// Added for Subdir
bool is_path(char* path);
struct dir_entry* get_dir_entry_from_path(char* path);
struct dir* get_dir_from_path(char* path);
struct dir* get_dir_from_entry(struct dir_entry* entry);
struct dir_entry* lookup_from_path(char* name);
struct dir_entry* lookup_only_parent(char* name);
char* get_filename_from_path(char* name);
bool is_file_name(char* path);
//static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp);
#endif /* filesys/directory.h */
