#include "threads/pte.h"
#include "lib/stdint.h"



/* 
    Returns true if ptr is invalid or otherwise outside of user memory.
*/
void is_valid_ptr(void *ptr) {
  if (ptr == NULL || (uint32_t)ptr == 0 || !is_user_vaddr(ptr)) { 
    // ptr < 0 gets compile error (int and pointer comparison)
    // PTE_P from pte.h
    return false;
  }
  return true;
}