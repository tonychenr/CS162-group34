#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include <syscall-nr.h> 

// static char buf[64000];

void
test_main (void) 
{
	// No return value, should just reset buffer cache.
	int handle;
	int count;
	int byte_cnt;
	char data[0];
  	char buf[0];
	data[0] = 1;
	reset_sys ();
	CHECK (create ("temp_test.txt", 64000), "create \"temp_test.txt\"");
	CHECK ((handle = open ("temp_test.txt")) > 1, "open \"temp_test.txt\"");
	count = 1;
	while (count <= 64000) {
		byte_cnt = write (handle, &data, 1);
		if (byte_cnt != 1) {
  			fail ("write() returned %d instead of %zu", byte_cnt, 1);
		}
		count++;
	}
	count = 1;
	while (count <= 64000) {
		byte_cnt = read (handle, &buf, 1);
		count++;
	}
	int dev_writes_total = device_writes_sys();
	CHECK (dev_writes_total <= 128, "not the expected order of writes");
}