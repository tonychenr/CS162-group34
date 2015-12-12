#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_write_back_on_shutdown();
  free_map_close ();
}


/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int
get_next_part (char part[NAME_MAX + 1], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes. If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST. Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
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

static struct dir *get_cwd (const char *name) {
  struct dir *search_dir = NULL;
  if (name[0] == '/') {
    search_dir = dir_open_root();
  } else {
    struct dir *cwd = thread_current()->cwd;
    if (cwd != NULL) {
      search_dir = dir_reopen(cwd);
    } else if (thread_current()->parent_data != NULL && thread_current()->parent_data->cwd != NULL) {
      search_dir = dir_reopen(thread_current()->parent_data->cwd);
    } else {
      search_dir = dir_open_root();
    }
  }

  return search_dir;
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, uint32_t is_dir) 
{
  block_sector_t inode_sector = (block_sector_t) -1;
  struct inode *inode = NULL;
  struct dir *search_dir = get_cwd(name);

  if (search_dir == NULL) {
    return NULL;
  }

  char part[NAME_MAX + 1];
  int retrieved_next_part;
  for (retrieved_next_part = get_next_part(part, &name); retrieved_next_part > 0;
       retrieved_next_part = get_next_part(part, &name)) {
    if (dir_lookup (search_dir, part, &inode)) {
      if (!inode_is_dir(inode)) {
        break;
      } else {
        dir_close(search_dir);
        search_dir = dir_open(inode);
      }
    } else {
      inode = NULL;
      break;
    }
  }
  if (inode != NULL && retrieved_next_part == 0) {
    inode = inode_reopen(inode);
  } else {
    inode_close(inode);
    dir_close(search_dir);
    return false;
  }
  dir_close(search_dir);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
  struct inode *inode = NULL;
  struct dir *search_dir = get_cwd(name);

  if (search_dir == NULL) {
    return NULL;
  }

  char part[NAME_MAX + 1];
  int retrieved_next_part;
  for (retrieved_next_part = get_next_part(part, &name); retrieved_next_part > 0;
       retrieved_next_part = get_next_part(part, &name)) {
    if (dir_lookup (search_dir, part, &inode)) {
      if (!inode_is_dir(inode)) {
        break;
      } else {
        dir_close(search_dir);
        search_dir = dir_open(inode);
      }
    } else {
      inode = NULL;
      break;
    }
  }
  if (inode != NULL && retrieved_next_part == 0) {
    inode = inode_reopen(inode);
  }
  dir_close(search_dir);
  
  if (inode != NULL && get_next_part(part, &name) != 0) {
    inode_close(inode);
    inode = NULL;
  }

  return inode;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct inode *inode = NULL;
  struct dir *search_dir = get_cwd(name);
  struct dir *parent_dir = NULL;

  if (search_dir == NULL) {
    return false;
  }

  parent_dir = dir_reopen(search_dir);
  char part[NAME_MAX + 1];
  int retrieved_next_part;
  for (retrieved_next_part = get_next_part(part, &name); retrieved_next_part > 0;
       retrieved_next_part = get_next_part(part, &name)) {
    if (dir_lookup (search_dir, part, &inode)) {
      if (!inode_is_dir(inode)) {
        break;
      } else {
        dir_close(parent_dir);
        parent_dir = dir_reopen(search_dir);
        dir_close(search_dir);
        search_dir = dir_open(inode);
      }
    } else {
      inode = NULL;
      break;
    }
  }
  if (inode != NULL && retrieved_next_part == 0) {
    inode = inode_reopen(inode);
  }
  dir_close(search_dir);
  
  if (parent_dir == NULL) {
    inode_close(inode);
    return false;
  }

  if (inode != NULL && get_next_part(part, &name) != 0) {
    inode_close(inode);
    dir_close(parent_dir);
    return false;
  }
  char buffer[NAME_MAX + 1];
  if (inode_is_open(inode) || dir_readdir(parent_dir, buffer)) {
    inode_close(inode);
    dir_close(parent_dir);
    return false;
  }

  bool success = dir_remove (parent_dir, part);
  dir_close(parent_dir);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
