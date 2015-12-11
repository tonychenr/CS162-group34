#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "../syscall-nr.h"

static char buf;

void
test_main (void) 
{
	// No return value, should just reset buffer cache.
	int handle;
	int hit_count1;
	int hit_count2;
	syscall0(SYS_RESET);
	handle = open("full_cache_sample.txt");
	// Should not be any hits after resetting cache
  	read (handle, &buf, 512 * 16);
	hit_count1 = syscall0(SYS_HITS);
	close(handle);
	handle = open("full_cache_sample.txt");
	// Should be about 64 hits or so
	read (handle, &buf, 512 * 16);
	hit_count2 = syscall0(SYS_HITS);
	close(handle);
	CHECK (hit_count1 < hit_count2, "number of hits is greater the second time");
}
