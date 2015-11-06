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
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <list.h>
#include <debug.h>

static void syscall_handler (struct intr_frame *);
static void halt_handler (void);
void exit_handler (int status);
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
static struct lock ref_count_lock; /* Lock for accessing ref_count in shared data */
static int number_arguments[14]; /* number_arguments[syscall_number] gives the number of arguments for syscall */
static int global_fd; /* Index of file descriptors */

static struct file_struct *get_file (int fd) {
  struct list_elem *e;
  struct file_struct *nextFile;
  struct file_struct *matchedFile = NULL;
  struct list *file_structs = &thread_current()->files;
  for (e = list_begin (file_structs); e != list_end (file_structs); e = list_next (e)) {
    nextFile = list_entry(e, struct file_struct, elem);
    if (nextFile->fd == fd)
      break;
  }
  return matchedFile;
}

static int create_fd (void) {
  global_fd++;
  return global_fd;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&ref_count_lock);
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
  global_fd = 2;
}

static void halt_handler (void) {
  shutdown_power_off();
}

void exit_handler (int status) {

  printf("%s: exit(%d)\n", &thread_current ()->name, status);

  lock_acquire(&ref_count_lock);
  struct p_data* parent = thread_current()->parent_data;
  if (parent != NULL) {
    parent->exit_status = status;
    parent->child_thread = NULL;
    sema_up(&parent->sema);
    parent->ref_count --;
    if (parent->ref_count == 0) {
      thread_current()->parent_data = NULL;
      free(parent);

    }
  }

  /* iterate through children and remove this as their parent*/
  struct list_elem* e;
  struct list *childs = &thread_current()->child_processes;
  for (e = list_begin(childs); e != list_end(childs); e = list_next(e)) {
    struct p_data* child = list_entry(e, struct p_data, elem);
    child->ref_count --;
    list_remove(e);
    if (child->ref_count == 0) {
      struct thread *t = child->child_thread;
      if (t != NULL) {
        t->parent_data = NULL;
      }
      free(child);
    }
  }

  struct list *files = &thread_current()->files;
  for (e = list_begin(files); e != list_end(files); e = list_begin(files)) {
    close_handler(list_entry(e, struct file_struct, elem)->fd);
  }
  lock_release(&ref_count_lock);
  thread_exit();
}

static pid_t exec_handler (char *file) {
  if (file == NULL) {
    return -1;
  } else {
    pid_t tid = process_execute (file);
    return tid;
  }
}

static int wait_handler (pid_t pid) {
  int exit_status = process_wait(pid);
  return exit_status;

}

static bool create_handler (const char *file, unsigned initial_size) {
  return false;
}

static bool remove_handler (const char *file) {
  return false;
}

static int open_handler (const char *file) {
  if (file == NULL) {
    return -1;
  }
  struct file *f = filesys_open(file);
  struct thread *t = thread_current();
  if (f == NULL) {
    return -1;
  }
  struct file_struct *fstruct = malloc(sizeof(struct file_struct));
  if (fstruct == NULL) {
    file_close(f);
    return -1;
  }
  list_push_back(&t->files, &fstruct->elem);
  fstruct->fd = create_fd();
  fstruct->sys_file = f;
  return fstruct->fd;
}

static int filesize_handler (int fd) {
  return 0;
}

static int read_handler (int fd, void *buffer, unsigned size) {
  return 0;
}

static int write_handler (int fd, const void *buffer, unsigned size) {
  if (!is_user_vaddr(buffer + size) || pagedir_get_page(thread_current()->pagedir, buffer) == NULL) {
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
    if (write_file != NULL) {
      num_bytes_written = file_write(write_file->sys_file, buffer, size);
    }
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
  struct file_struct *f = get_file(fd);
  if (f != NULL) {
    list_remove(&f->elem);
    file_close(f->sys_file);
    free(f);
  }
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
    exit_handler(-1);
  } else {
    physical_addr = pagedir_get_page (pd, args);
    if (physical_addr == NULL) {
      exit_handler(-1);
    }
    syscall_number = args[0];
    int i;
    for (i = 0; i <= number_arguments[syscall_number]; i++) {
      if (!is_user_vaddr(args + i)) {
        exit_handler(-1);
      } else {
        physical_addr = pagedir_get_page (pd, args + i);
        if (physical_addr == NULL) {
          exit_handler(-1);
        }
      }
    }
    switch (syscall_number) {
      case SYS_HALT:
        halt_handler ();
        break;
      case SYS_EXIT:
        exit_handler((int) args[1]);
        break;
      case SYS_EXEC:
        f->eax = exec_handler ((char *) args[1]);
        break;
      case SYS_WAIT:
        f->eax = wait_handler ((pid_t) args[1]);
        break;
      case SYS_CREATE:
        f->eax = create_handler ((char *) args[1], (unsigned) args[2]);
        break;
      case SYS_REMOVE:
        f->eax = remove_handler ((char *) args[1]);
        break;
      case SYS_OPEN:
        f->eax = open_handler ((char *) args[1]);
        break;
      case SYS_FILESIZE:
        f->eax = filesize_handler ((int) args[1]);
        break;
      case SYS_READ:
        f->eax = read_handler ((int) args[1], (void *) args[2], (unsigned) args[3]);
        break;
      case SYS_WRITE:
        f->eax = write_handler ((int) args[1], (void *) args[2], (unsigned) args[3]);
        break;
      case SYS_SEEK:
        seek_handler ((int) args[1], (unsigned) args[2]);
        break;
      case SYS_TELL:
        f->eax = tell_handler ((int) args[1]);
        break;
      case SYS_CLOSE:
        close_handler ((int) args[1]);
        break;
      case SYS_PRACTICE:
        f->eax = practice_handler ((int) args[1]);
        break;
    }
  }
}

