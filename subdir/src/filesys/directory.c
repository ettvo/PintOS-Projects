#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"


// /* A single directory entry. Refers to a file that can be either a directory or a normal file. */
// struct dir_entry {
//   block_sector_t inode_sector; /* Sector number of header. */
//   char name[NAME_MAX + 1];     /* Null terminated file name. */
//   bool in_use;                 /* In use or free? */
// };

static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp);

/* Need to call dir_close on directory after returning. */
struct dir* get_dir_from_entry(struct dir_entry* entry) {
  if (entry == NULL) return NULL;
  // assumes in_use
  // should find a more efficient way to do this
  struct inode* inode = inode_open(entry->inode_sector);
  if (is_directory(inode)) {
    struct dir* dir = dir_open(inode);
    return dir; // dir_close should be called by caller
  }
  inode_close(inode); 
  return NULL;
}

/* Returns NULL if something fails.*/
struct dir* get_dir_from_path(char* path) {
  if (path == NULL || path[0] == '\0') return NULL;
  if (strcmp(path, ".") == 0) {
    return thread_current()->pcb->cwd;
  }
  else if (strcmp(path, "..") == 0) {
    return thread_current()->pcb->cwd->parent;
  }
  return get_dir_from_entry(lookup_from_path(path));
}

bool is_path(char* path) {
  if (path == NULL || path[0] != '\0') {
    return false;
  }
  if (strchr(path, '/') != NULL)
  
  return true;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

// Avoid checking if the filename at the end is valid.

struct dir_entry* lookup_only_parent(char* name) {
  if (name == NULL || name[0] == '\0') return NULL;
  char* filename = strrchr(name, '/');
  if (filename != NULL) {
    char parent_path[strlen(name) - strlen(filename) + 1];
    strlcpy(parent_path, name, strlen(name) - strlen(filename));
    parent_path[strlen(name) - strlen(filename)] = '\0';
    return lookup_from_path(parent_path);
  }
  else {
    return lookup_from_path(name);
  }
}

bool is_file_name(char* path) {
  if (path == NULL || path[0] == '\0') return false;
  char* last = strrchr(path, '/');
  if (last == NULL) {
    if (strrchr(path, ".") != NULL) return true;
    return false;
  }
  if (strrchr(last, ".") != NULL) return true;
  return false;
}

char* get_filename_from_path(char* name) {
  if (name == NULL || name[0] == '\0') return NULL;
  char* filename = strrchr(name, '/');
  if (filename != NULL) {
    return filename + sizeof(char);
  }
  else {
    return name;
  }
}

// Close dir as necessary to avoid leakage
struct dir_entry* lookup_from_path(char* name) {
  if (name[0] == '\0' || name == NULL) return NULL;
  char filename[NAME_MAX + 1];
  struct dir* curr = NULL;
  //struct dir* prev;
  struct dir_entry* ret = NULL;

  if (name[0] == '/') {
    curr = dir_open_root();
    dir_close(curr);
  }
  else {
    curr = thread_current()->pcb->cwd;
  }
  bool is_root = inode_get_inumber(curr->inode) == ROOT_DIR_SECTOR;
  int len = strlen(name);
  char* curr_path[len + 1];
  strlcpy(*curr_path, name, len + 1);
  //prev = curr;
  // char* p = &a[0] 
  // const char** srcp
  // update parent as we go
  
  while (strchr(*curr_path, '/') != NULL) {
    // if (get_next_part(filename, &curr_path[0]) == -1) {
    if (curr != NULL) dir_close(curr);
    if (get_next_part(filename, curr_path) == -1) {
      return NULL; // indicates that input directory doesnt exist
    }
    if (strcmp(filename, "..") == 0) {
      if (is_root) return NULL; // invalid path, root has no parent
      curr = curr->parent;
    }
    else if (strcmp(filename, ".") == 0) {
      // do nothing
    }
    else {
      if (!lookup(curr, filename, ret, NULL)) {
        return NULL; 
      }
      // dir_close(curr);
      curr = get_dir_from_entry(ret);

      //curr->parent = prev;
    }
  }

  lookup(curr, filename, ret, NULL); // should be on filename / last dir
  if (ret != NULL && ret->in_use == false) return NULL;
  return ret;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  struct inode* inode;
  bool status = inode_create(sector, entry_cnt * sizeof(struct dir_entry));
  // add flag here to inode
  if (status) {
    inode = inode_open(sector);
    struct dir* curr = dir_open(inode);
    set_dir_status(inode, true);
    inode_close(inode);
    curr->parent = thread_current()->pcb->cwd;
    dir_close(curr);
    return status;
    // update both dir status and parent
  }
  return status;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}


// original lookup
// looks in DIR for NAME and stores the corresponding dir_entry in EP with offset OFSP
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  struct dir* curr = dir;
  // TODO: check for name in current directory, then move to DIR
  // if (strnchr(name, '/') != NULL) { // name is a path 
    
  //   struct dir* curr = get_dir_from_path(name); // would need to remove name of file
  //   if (curr == NULL) {
  //     goto done;
  //   } 
  // }

  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  e.entry_count += 1;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  bool can_delete = false;
  e.entry_cnt -= 1;
  if (is_directory(inode)) {
    // check if empty first
    // inode_close if not and return success
    if (e.entry_count == 0) can_delete = true;
    
  }
  else { 
    can_delete = true;
  }

  if (can_delete) {
    /* Erase directory entry. */
    e.in_use = false;
    if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
      goto done;
    /* Remove inode. */
    inode_remove(inode);
    success = true;
  }
  

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}
