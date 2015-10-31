#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void practice_handler (struct intr_frame *, int);
static void halt_handler (struct intr_frame *);
static void exit_handler (struct intr_frame *, int);
static void exec_handler (struct intr_frame *, char *);
static void wait_handler (struct intr_frame *,pid_t);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t* args = ((uint32_t*) f->esp);
  printf("System call number: %d\n", args[0]);

  switch (args[0]) {	
	case SYS_PRACTICE:
		practice_handler (f, (int)args[1]);
	case SYS_HALT:
		halt_handler (f);
	case SYS_EXIT:
		exit_handler (f, (int)args[1]);
	case SYS_EXEC:
		exec_handler (f, (char *)args[1]);
	case SYS_WAIT:
	case SYS_CREATE:
	case SYS_REMOVE:
	case SYS_OPEN:
	case SYS_FILESIZE:
	case SYS_READ:
	case SYS_WRITE:
	case SYS_SEEK:
	case SYS_TELL:
	case SYS_CLOSE:

  }
}


static void practice_handler (struct intr_frame *f, int i) {
	f->eax = i + 1;
}

static void halt_handler (struct intr_frame *f) {
	shutdown_power_off();
}

static void exit_handler (struct intr_frame *f, int status) {
	f->eax = status;
	
    thread_exit();
}

static void exec_handler (struct intr_frame *f, char *file) {

}

static void wait_handler (struct intr_frame *f, pid_t pid) {

}