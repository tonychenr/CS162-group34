#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);
static void halt_handler (void);
static void exit_handler (struct intr_frame *f, int status);
static pid_t exec_handler (char *file);
static int wait_handler (pid_t pid);
static bool create_handler (const char *file, unsigned initial_size);
static bool remove_handler (const char *file);
static int open_handler (const char *file);
static int filesize_handler (int fd);
static int read_handler (int fd, void *buffer, unsigned size);
static int write_handler (int fd, const void *buffer, unsigned size);
static void seek_handler (int fd, unsigned position);
static unsigned tell_handler (int fd);
static void close_handler (int fd);
static int practice_handler (int i);

struct lock file_lock; /* Lock accessing file system */
int number_arguments[10]; /* number_arguments[syscall_number] gives the number of arguments for syscall */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  number_arguments[SYS_HALT] = 0;
  number_arguments[SYS_EXIT] = 1;
  number_arguments[SYS_EXEC] = 1;
  number_arguments[SYS_WAIT] = 1;
  number_arguments[SYS_CREATE] = 2;
  number_arguments[SYS_REMOVE] = 1;
  number_arguments[SYS_OPEN] = 1;
  number_arguments[SYS_FILESIZE] = 1;
  number_arguments[SYS_READ] = 3;
  number_arguments[SYS_WRITE] = 3;
  number_arguments[SYS_SEEK] = 2;
  number_arguments[SYS_TELL] = 1;
  number_arguments[SYS_CLOSE] = 1;
  number_arguments[SYS_PRACTICE] = 1;
}

static void halt_handler (void) {
  shutdown_power_off();
}

static void exit_handler (struct intr_frame *f, int status) {
  f->eax = status;
  printf("%s: exit(%d)\n", &thread_current ()->name, status);
  thread_exit();
}

static pid_t exec_handler (char *file) {
  return 0;
}

static int wait_handler (pid_t pid) {
  return 0;
}

static bool create_handler (const char *file, unsigned initial_size) {
  return false;
}

static bool remove_handler (const char *file) {
  return false;
}

static int open_handler (const char *file) {
  return 0;
}

static int filesize_handler (int fd) {
  return 0;
}

static int read_handler (int fd, void *buffer, unsigned size) {
  return 0;
}

static int write_handler (int fd, const void *buffer, unsigned size) {
  return 0;
}

static void seek_handler (int fd, unsigned position) {
  return;
}

static unsigned tell_handler (int fd) {
  return 0;
}

static void close_handler (int fd) {
  return;
}

static int practice_handler (int i) {
  return i + 1;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t* addr = ((uint32_t*) f->esp);
  uint32_t* pd = thread_current()->pagedir;
  int syscall_number;
  int args[3] = {0, 0, 0};
  int *physical_addr;
  if (!is_user_vaddr(addr)) {
    exit_handler(f, -1);
  } else {
    physical_addr = pagedir_get_page (pd, addr);
    if (physical_addr == NULL) {
      exit_handler(f, -1);
    }
    syscall_number = (int) *physical_addr;
    printf("System call number: %d\n", syscall_number);
    int i;
    for (i = 0; i < number_arguments[syscall_number]; i++) {
      if (!is_user_vaddr(addr + i)) {
        exit_handler(f, -1);
      } else {
        physical_addr = pagedir_get_page (pd, addr + i);
        if (physical_addr == NULL) {
          exit_handler(f, -1);
        } else {
          args[i] = (int) *physical_addr;
        }
      }
    }
    switch (syscall_number) {
      case SYS_HALT:
        halt_handler ();
      case SYS_EXIT:
        exit_handler(f, (int) args[0]);
      case SYS_EXEC:
        f->eax = exec_handler ((char *) args[0]);
      case SYS_WAIT:
        f->eax = wait_handler ((pid_t) args[0]);
      case SYS_CREATE:
        f->eax = create_handler ((char *) args[0], (unsigned) args[1]);
      case SYS_REMOVE:
        f->eax = remove_handler ((char *) args[0]);
      case SYS_OPEN:
        f->eax = open_handler ((char *) args[0]);
      case SYS_FILESIZE:
        f->eax = filesize_handler ((int) args[0]);
      case SYS_READ:
        f->eax = read_handler ((int) args[0], (void *) args[1], (unsigned) args[2]);
      case SYS_WRITE:
        f->eax = write_handler ((int) args[0], (void *) args[1], (unsigned) args[2]);
      case SYS_SEEK:
        seek_handler ((int) args[0], (unsigned) args[1]);
      case SYS_TELL:
        f->eax = tell_handler ((int) args[0]);
      case SYS_CLOSE:
        close_handler ((int) args[0]);
      case SYS_PRACTICE:
        f->eax = practice_handler ((int) args[0]);
    }
  }
}
