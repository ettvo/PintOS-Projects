#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

struct lock inode_write_lock;

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INDIRECT_BLOCK_CNT 128
#define DP_CNT 122 

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// 512B
struct inode_disk {
  //block_sector_t start; /* First data sector. */
  // 4 + 4 + 496 + 4 + 4 = 512
  off_t length;         /* File size in bytes. */ //4
  unsigned magic;       /* Magic number. */ //4
  int block_index;
  int is_dir; /*0 if file, 1 if directory*/
  block_sector_t dp[DP_CNT]; // typedef uint32_t block_sector_t;        
  block_sector_t ip;  // block index
  block_sector_t dip; // pointer to a pointer to direct block
  //uint32_t unused[125]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

bool is_directory(struct inode* inode) {
  return inode->data.is_dir;
}

void set_dir_status(struct inode* inode, bool status) {
  inode->data.is_dir = status;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

// compute the sector number from the offset
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
    // pos is in bytes
  // char buffer[BLOCK_SECTOR_SIZE];
  // block_read(fs_device, inode->sector, buffer);
  // struct inode_disk *disk_inode = (struct inode_disk *) buffer;

  struct inode_disk *disk_inode = &inode -> data;

  if (pos > disk_inode -> length) return -1;

  if (pos <  disk_inode -> length) {
    // Calculate the index of the direct block based on the position
    int block_index = pos / BLOCK_SECTOR_SIZE;

    // Check if the index is within the range of direct pointers
    if (block_index < DP_CNT) {
      return disk_inode -> dp[block_index];
    }

    // Add logic for handling indirect and doubly indirect pointers if needed
    if (block_index < DP_CNT + INDIRECT_BLOCK_CNT) {
      int indirect_index = block_index - DP_CNT;
      block_sector_t indirect_block[INDIRECT_BLOCK_CNT];

      // Im sure it is just indirect_block without pointer
      block_read(fs_device, disk_inode -> ip, indirect_block);
      return indirect_block[indirect_index];
    }

    if (block_index < DP_CNT + INDIRECT_BLOCK_CNT + INDIRECT_BLOCK_CNT*INDIRECT_BLOCK_CNT) {
      // Calculate the indices within the doubly indirect block
      int doubly_indirect_index = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) / INDIRECT_BLOCK_CNT;
      int doubly_indirect_offset = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) % INDIRECT_BLOCK_CNT;

      // Read the doubly indirect block
      block_sector_t doubly_indirect_block[INDIRECT_BLOCK_CNT];
      block_read(fs_device, disk_inode -> dip, doubly_indirect_block);

      // Read the indirect block from the doubly indirect block
      block_sector_t indirect_block[INDIRECT_BLOCK_CNT];
      block_read(fs_device, doubly_indirect_block[doubly_indirect_index], indirect_block);

      // Return the sector from the indirect block
      return indirect_block[doubly_indirect_offset];
    }
  }

  // Return -1 for cases where the position is beyond the allocated space
  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }


bool inode_create_helper(size_t sectors, struct inode_disk *disk_inode, int block_index) {
  static char zeros[BLOCK_SECTOR_SIZE];
  
  for (; block_index < sectors ; block_index++) {
    // allocating indirect pointer block
    if(block_index == DP_CNT) {
      // writes a block number
      free_map_allocate(1, &disk_inode->ip);
    }

    // allocate doubly indirect pointer block <- only once
    if (block_index == DP_CNT + INDIRECT_BLOCK_CNT) {
      free_map_allocate(1, &disk_inode->dip);
    }
    
    // allocate indirect pointer block of the doubly indirectly pointer blocks <- each time indirect pointer block is full allocate a new one
    if (block_index >= DP_CNT + INDIRECT_BLOCK_CNT) {
      int doubly_indirect_index = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) / INDIRECT_BLOCK_CNT;
      int doubly_indirect_offset = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) % INDIRECT_BLOCK_CNT;
      if (doubly_indirect_offset == 0) {
        // get the current block of indirect pointers (pointed to by the doubly indirect pointer)
        block_sector_t doubly_indirect_block[INDIRECT_BLOCK_CNT];
        block_read(fs_device, disk_inode -> dip, doubly_indirect_block);

        // Update the doubly_indirect_index-th indirect pointer in the block
        free_map_allocate(1, &doubly_indirect_block[doubly_indirect_index]);
        
        //write the updated indirect pointer block back  to disk
        block_write(fs_device, disk_inode -> dip, doubly_indirect_block);
      }
    }

    // allocating data blocks
    if (block_index < DP_CNT) {
      free_map_allocate(1, &disk_inode->dp[block_index]);
      block_write(fs_device, disk_inode->dp[block_index], zeros);
    } else if (block_index < DP_CNT + INDIRECT_BLOCK_CNT) {
      int indirect_index = block_index - DP_CNT;
      block_sector_t indirect_block[INDIRECT_BLOCK_CNT];

      // Im sure it is just indirect_block without pointer
      // Update indirect block (get new indirect pointer and associated data block)
      block_read(fs_device, disk_inode -> ip, indirect_block);
      free_map_allocate(1, &indirect_block[indirect_index]); 

      // Write updated indirect block back to disk
      block_write(fs_device, disk_inode->ip, indirect_block);

      // Zero out newly created data block
      block_write(fs_device, indirect_block[indirect_index], zeros);
      
    } else if (block_index < 123 + INDIRECT_BLOCK_CNT + INDIRECT_BLOCK_CNT*INDIRECT_BLOCK_CNT) {
      // Calculate the indices within the doubly indirect block
      int doubly_indirect_index = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) / INDIRECT_BLOCK_CNT;
      int doubly_indirect_offset = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) % INDIRECT_BLOCK_CNT;

      // Read the doubly indirect block
      block_sector_t doubly_indirect_block[INDIRECT_BLOCK_CNT];
      block_read(fs_device, disk_inode -> dip, doubly_indirect_block);

      // Read the indirect block from the doubly indirect block
      block_sector_t indirect_block[INDIRECT_BLOCK_CNT];
      block_read(fs_device, doubly_indirect_block[doubly_indirect_index], indirect_block);

      // save the block address of the block allocated
      free_map_allocate(1, &indirect_block[doubly_indirect_offset]);

      // write updated direct pointer block back to disk
      block_write(fs_device, doubly_indirect_block[doubly_indirect_index], indirect_block);

      // zero out new data block
      block_write(fs_device, indirect_block[doubly_indirect_offset], zeros);
    } else {
      printf("Too big!!!");
    }
    disk_inode -> block_index = block_index;
  }

  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) { // sector is where inode should be created. Length is the size of the files
  struct inode_disk* disk_inode = NULL;
  //bool success = false;
  //for now always returns true
  bool success = true;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length); // number of sectors that has to be allocated will remain the same
    disk_inode->length = length; // length is file size in bytes
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = false;
    // continuous allocation
    // modify the code to save the block addresses of all blocks allocated

    // when you declare a static array with the static keyword, 
    // the elements are automatically initialized to zero if no explicit initializer is provided. 
    // Therefore, in this case, the array zeros will be filled with zero values for each element.
    static char zeros[BLOCK_SECTOR_SIZE];

    // zero out the sector that will hold the new inode 
    block_write(fs_device, sector, zeros);

    // initialize inode fields
    inode_create_helper(sectors, disk_inode, 0);

    block_write(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      // todo
      free_map_release(inode->sector, 1);

      // free disk
      // char buffer[BLOCK_SECTOR_SIZE];
      // block_read(fs_device, inode->sector, buffer);
      // struct inode_disk *disk_inode = (struct inode_disk *) buffer;
      struct inode_disk* disk_inode = &inode->data;
      int sectors = disk_inode->length;
      // free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
      for (int block_index = sectors-1 ; block_index >= 0 ; block_index--) {

        // allocating data blocks
        if (block_index < DP_CNT) {
          //free_map_allocate(1, &disk_inode->dp[block_index]);
          free_map_release(disk_inode->dp[block_index], 1);
          //block_write(fs_device, &disk_inode->dp[block_index], zeros);
        } else if (block_index < DP_CNT + INDIRECT_BLOCK_CNT) {
          int indirect_index = block_index - DP_CNT;
          block_sector_t indirect_block[INDIRECT_BLOCK_CNT];

          // Im sure it is just indirect_block without pointer
          // Update indirect block (get new indirect pointer and associated data block)
          block_read(fs_device, disk_inode -> ip, indirect_block);
          // free_map_allocate(1, &indirect_block[indirect_index]);
          free_map_release(indirect_block[indirect_index], 1);

        } else if (block_index < DP_CNT + INDIRECT_BLOCK_CNT + INDIRECT_BLOCK_CNT*INDIRECT_BLOCK_CNT) {
          // Calculate the indices within the doubly indirect block
          int doubly_indirect_index = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) / INDIRECT_BLOCK_CNT;
          int doubly_indirect_offset = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) % INDIRECT_BLOCK_CNT;

          // Read the doubly indirect block
          block_sector_t doubly_indirect_block[INDIRECT_BLOCK_CNT];
          block_read(fs_device, disk_inode -> dip, doubly_indirect_block);

          // Read the indirect block from the doubly indirect block
          block_sector_t indirect_block[INDIRECT_BLOCK_CNT];
          block_read(fs_device, doubly_indirect_block[doubly_indirect_index], indirect_block);

          // free the block address of the block allocated
          free_map_release(indirect_block[doubly_indirect_offset], 1);
        }

                // allocating indirect pointer block
        if(block_index == DP_CNT) {
          // writes a block number
          free_map_release(disk_inode->ip, 1);
        }
        
        // allocate indirect pointer block of the doubly indirectly pointer blocks <- each time indirect pointer block is full allocate a new one
        if (block_index >= DP_CNT + INDIRECT_BLOCK_CNT) {
          int doubly_indirect_index = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) / INDIRECT_BLOCK_CNT;
          int doubly_indirect_offset = (block_index - DP_CNT - INDIRECT_BLOCK_CNT) % INDIRECT_BLOCK_CNT;
          if (doubly_indirect_offset == 0) {
            // get the current block of indirect pointers (pointed to by the doubly indirect pointer)
            block_sector_t doubly_indirect_block[INDIRECT_BLOCK_CNT];
            block_read(fs_device, disk_inode -> dip, doubly_indirect_block);

            // Update the doubly_indirect_index-th indirect pointer in the block
            // free_map_allocate(1, &doubly_indirect_block[doubly_indirect_index]);
            free_map_release(doubly_indirect_block[doubly_indirect_index], 1);
          }
        }

        // allocate doubly indirect pointer block <- only once
        if (block_index == DP_CNT + INDIRECT_BLOCK_CNT) {
          free_map_release(disk_inode->dip, 1);
        }

      }
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
  // allocate lock
  // lock_acquire(&inode_write_lock);

  // char inode_buffer[BLOCK_SECTOR_SIZE];
  // block_read(fs_device, inode->sector, inode_buffer);
  // struct inode_disk *disk_inode = (struct inode_disk *) inode_buffer;
  struct inode_disk* disk_inode = &inode->data;
  int final_end = offset + size  - 1;
  int limit = disk_inode->length;

  if ((limit == 0) && (final_end != limit)) {
    size_t additional_blocks = 1 + (final_end / BLOCK_SECTOR_SIZE);
    int block_index = 0;
    int end_block = additional_blocks + block_index;
    inode_create_helper(end_block, disk_inode, block_index);

  } else if (final_end > limit) {
    // update file size is equivalent to updating inode
    
    size_t additional_blocks = 0;
    // if final and limit are part of the same block, we don't need to allocate new blocks
    if ((final_end / BLOCK_SECTOR_SIZE) != (limit / BLOCK_SECTOR_SIZE)) {
      additional_blocks = (final_end / BLOCK_SECTOR_SIZE) - (limit / BLOCK_SECTOR_SIZE);
    }

    // find where the inode_disk is at from 'limit'
    block_sector_t sector_idx = byte_to_sector(inode, limit);

    // allocate the necessary amount of data blocks
    int block_index = disk_inode -> length / BLOCK_SECTOR_SIZE + 1;
    int end_block = additional_blocks + block_index;
    inode_create_helper(end_block, disk_inode, block_index);
  }

  disk_inode->length = (offset + size > limit) ? offset + size : limit;
  block_write(fs_device, inode -> sector, disk_inode);
  memcpy(&inode -> data, disk_inode, BLOCK_SECTOR_SIZE);

  // release lock
  // lock_release(&inode_write_lock);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { 
  // return inode->data.length; 
  char buffer[BLOCK_SECTOR_SIZE];
  block_read(fs_device, inode -> sector, buffer);
  struct inode_disk *disk_inode = (struct inode_disk *) buffer;
  return disk_inode -> length;
  // return inode->data.length;
}
