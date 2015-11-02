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
#include "lib/kernel/console.h"
#include "devices/input.h"
#include <list.h>

struct file_struct {
  struct file *sysFile;       /* Actual file struct in filesys/file.c */
  int fd;                     /* File descriptor */
  int ref_count;              /* Number of processes referencing this file */
  bool removed;               /* True if a process removed this file. */
  struct list_elem elem;      /* List elem for syscall file list */
};

static void syscall_handler (struct intr_frame *);
static void halt_handler (void);
static void exit_handler (int status);
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

static struct lock file_lock; /* Lock accessing file system */
int number_arguments[10]; /* number_arguments[syscall_number] gives the number of arguments for syscall */
struct list file_structs; /* List of open files */

static struct file_struct *get_file (int fd) {
  struct list_elem *e;
  struct file_struct *nextFile;
  struct file_struct *matchedFile = NULL;
  for (e = list_begin (&file_structs); e != list_end (&file_structs); e = list_next (e)) {
    nextFile = list_entry(e, struct file_struct, elem);
    if (nextFile->fd == fd)
      break;
  }
  return matchedFile;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  list_init(&file_structs);
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

static void exit_handler (int status) {
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
  if (!is_user_vaddr(buffer + size)) {
    exit_handler(-1);
  }

  int num_bytes_written = 0;
  lock_acquire(&file_lock);
  if (fd == STDIN_FILENO) {
    lock_release(&file_lock);
    exit_handler(-1);
  } else if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    num_bytes_written = size;
  } else {
    struct file_struct *write_file = get_file(fd);
    if (write_file == NULL) {
      lock_release(&file_lock);
      exit_handler(-1);
    }
    num_bytes_written = file_write(write_file->sysFile, buffer, size);
  }

  lock_release(&file_lock);
  return num_bytes_written;
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
  uint32_t* args = ((uint32_t*) f->esp);
  uint32_t* pd = thread_current()->pagedir;
  int syscall_number;
  int *physical_addr;
  if (!is_user_vaddr(args)) {
    f->eax = -1;
    exit_handler(-1);
  } else {
    physical_addr = pagedir_get_page (pd, args);
    if (physical_addr == NULL) {
      f->eax = -1;
      exit_handler(-1);
    }
    syscall_number = args[0];
    int i;
    for (i = 0; i < number_arguments[syscall_number]; i++) {
      if (!is_user_vaddr(args + i)) {
        f->eax = -1;
        exit_handler(-1);
      } else {
        physical_addr = pagedir_get_page (pd, args + i);
        if (physical_addr == NULL) {
          f->eax = -1;
          exit_handler(-1);
        }
      }
    }
    switch (syscall_number) {
      case SYS_HALT:
        halt_handler ();
      case SYS_EXIT:
        f->eax = (int) args[1];
        exit_handler((int) args[1]);
      case SYS_EXEC:
        f->eax = exec_handler ((char *) args[1]);
      case SYS_WAIT:
        f->eax = wait_handler ((pid_t) args[1]);
      case SYS_CREATE:
        f->eax = create_handler ((char *) args[1], (unsigned) args[2]);
      case SYS_REMOVE:
        f->eax = remove_handler ((char *) args[1]);
      case SYS_OPEN:
        f->eax = open_handler ((char *) args[1]);
      case SYS_FILESIZE:
        f->eax = filesize_handler ((int) args[1]);
      case SYS_READ:
        f->eax = read_handler ((int) args[1], (void *) args[2], (unsigned) args[3]);
      case SYS_WRITE:
        f->eax = write_handler ((int) args[1], (void *) args[2], (unsigned) args[3]);
      case SYS_SEEK:
        seek_handler ((int) args[1], (unsigned) args[2]);
      case SYS_TELL:
        f->eax = tell_handler ((int) args[1]);
      case SYS_CLOSE:
        close_handler ((int) args[1]);
      case SYS_PRACTICE:
        f->eax = practice_handler ((int) args[1]);
    }
  }
}

