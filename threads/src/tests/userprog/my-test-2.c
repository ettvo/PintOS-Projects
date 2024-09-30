/* Try writing a file in the most normal way. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt;

  CHECK(create("test2.txt", sizeof sample2 - 1), "create \"test2.txt\"");
  CHECK((handle = open("test2.txt")) > 1, "open \"test2.txt\"");

  byte_cnt = write(handle, sample2, sizeof sample2 - 1);
  if (byte_cnt != sizeof sample2 - 1)
    fail("write() returned %d instead of %zu", byte_cnt, sizeof sample2 - 1);
}
