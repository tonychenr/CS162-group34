#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_POINTER_COUNT 123
#define INDIRECT_BLOCK_POINTER_COUNT 128
#define UNALLOCATED_SECTOR (block_sector_t) -1

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    uint32_t is_dir;                    /* True if this is a directory sector. False if file sector*/
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct[123];         /* 8 Direct Block Pointers */
    block_sector_t indirect[2];         /* Indirect (i=0) and Double Indirect (i=1) pointers */
  };

typedef uint32_t block_sector_t;

static struct lock inode_list_lock;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  };


static void set_indirect_block (block_sector_t indirect) {
  uint8_t *bounce = malloc (BLOCK_SECTOR_SIZE);
  if (bounce == NULL)
    return;
  memset (bounce, -1, BLOCK_SECTOR_SIZE);
  block_write(fs_device, indirect, bounce);
  free(bounce);
}

static void set_direct_block (block_sector_t direct) {
  static char zeros[BLOCK_SECTOR_SIZE];
  block_write (fs_device, direct, zeros);
}

static block_sector_t allocate_block (void) {
  block_sector_t block_sector;
  free_map_allocate(1, &block_sector);
  return block_sector;
}

static block_sector_t allocate_block_direct (struct inode_disk *disk_inode, size_t sectors) {
  block_sector_t block_sector = disk_inode->direct[sectors];
  if (block_sector == UNALLOCATED_SECTOR) {
    block_sector =  allocate_block();
    set_direct_block(block_sector);
    disk_inode->direct[sectors] = block_sector;
  }
  return block_sector;
}

static block_sector_t handle_indirect (struct cache_block *temp_curr_block, size_t index, uint8_t indirection_level) {
  block_sector_t block_sector;

  block_sector_t *indirect_block = (block_sector_t *) temp_curr_block->data;
  block_sector = indirect_block[index];
  if (block_sector == UNALLOCATED_SECTOR) {
      block_sector = allocate_block();
      if (indirection_level == 2)
        set_indirect_block(block_sector);
      else
        set_direct_block(block_sector);
      indirect_block[index] = block_sector;
  }

  return block_sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  struct cache_block *temp_curr_block = cache_shared_pre(inode->sector);
  struct inode_disk *disk_inode = (struct inode_disk *) temp_curr_block->data;
  block_sector_t block_sector = UNALLOCATED_SECTOR;
  size_t sectors = pos / BLOCK_SECTOR_SIZE;
  if (sectors < DIRECT_POINTER_COUNT) {
    block_sector = allocate_block_direct(disk_inode, sectors);
    cache_shared_post(temp_curr_block, 1);
  } else {
    sectors -= DIRECT_POINTER_COUNT;
    if (sectors < INDIRECT_BLOCK_POINTER_COUNT) {
      block_sector_t indirect = disk_inode->indirect[0];
      if (indirect == UNALLOCATED_SECTOR) {
        indirect = allocate_block();
        set_indirect_block(indirect);
        disk_inode->indirect[0] = indirect;
      }
      cache_shared_post(temp_curr_block, 1);
      if (indirect != UNALLOCATED_SECTOR) {
        temp_curr_block = cache_shared_pre(indirect);
        block_sector = handle_indirect(temp_curr_block, sectors, 1);
        cache_shared_post(temp_curr_block, 1);
      }
      // printf("byte_to_sector: inode_sector=%u, pos=%u, sectors= %u, indirect=%u, allocated=%u\n", inode->sector, pos, sectors, indirect, block_sector);
    } else {
      sectors -= INDIRECT_BLOCK_POINTER_COUNT;
      size_t offset = sectors % INDIRECT_BLOCK_POINTER_COUNT;
      sectors = sectors / INDIRECT_BLOCK_POINTER_COUNT;
      block_sector_t doubly_indirect = disk_inode->indirect[1];
      if (doubly_indirect == UNALLOCATED_SECTOR) {
        doubly_indirect = allocate_block();
        set_indirect_block(doubly_indirect);
        disk_inode->indirect[1] = doubly_indirect;
      }
      cache_shared_post(temp_curr_block, 1);

      if (doubly_indirect != UNALLOCATED_SECTOR) {
        temp_curr_block = cache_shared_pre(doubly_indirect);
        block_sector_t indirect = handle_indirect(temp_curr_block, sectors, 2);
        cache_shared_post(temp_curr_block, 1);

        if (indirect != UNALLOCATED_SECTOR) {
          temp_curr_block = cache_shared_pre(indirect);
          block_sector = handle_indirect(temp_curr_block, offset, 1);
          cache_shared_post(temp_curr_block, 1);
        }
      }
    }
  }
  
  // printf("byte_to_sector: block_sector=%u\n", block_sector);
  return block_sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init(&inode_list_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  // printf("create: inode_sector=%u\n", sector);
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      memset(disk_inode->direct, -1, BLOCK_SECTOR_SIZE - 12);
      block_write (fs_device, sector, disk_inode);
      struct inode *inode = inode_open(sector);
      if (sectors > 0) 
        {
          inode_write_at (inode, "", 1, length - 1);
        }
      success = true; 
      inode_close(inode);
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  lock_acquire(&inode_list_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode->open_cnt++;
          lock_release(&inode_list_lock);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_release(&inode_list_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL) {
    lock_acquire(&inode_list_lock);
    inode->open_cnt++;
    lock_release(&inode_list_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

static void deallocate_sectors (block_sector_t blocks, uint32_t indirection_level) {
  if (blocks == UNALLOCATED_SECTOR) {
    return;
  }
  if (indirection_level == 0) {
    cache_invalidate_block(blocks);
    free_map_release(blocks, 1);
  } else {
    struct cache_block *temp_curr_block = cache_shared_pre(blocks);
    block_sector_t *sectors = (block_sector_t *) temp_curr_block->data;
    int i;
    for (i = 0; i < INDIRECT_BLOCK_POINTER_COUNT; i++) {
      deallocate_sectors(sectors[i], indirection_level - 1);
    }
    cache_shared_post(temp_curr_block, 0);
    cache_invalidate_block(blocks);
    free_map_release(blocks, 1);
  }
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode_list_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct cache_block *temp_curr_block = cache_shared_pre(inode->sector);
          struct inode_disk *disk_inode = (struct inode_disk *) temp_curr_block->data;
          int i;
          block_sector_t direct_sector = UNALLOCATED_SECTOR;
          for (i = 0; i < DIRECT_POINTER_COUNT; i ++) {
            direct_sector = disk_inode->direct[i];
            if (direct_sector != UNALLOCATED_SECTOR) {
              cache_invalidate_block(direct_sector);
              free_map_release(direct_sector, 1);
            }
          }
          deallocate_sectors(disk_inode->indirect[1], 2);
          deallocate_sectors(disk_inode->indirect[0], 1);
          cache_shared_post(temp_curr_block, 0);
          cache_invalidate_block(inode->sector);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
  lock_release(&inode_list_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  char *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      if (sector_idx == UNALLOCATED_SECTOR)
        break;
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      // printf("size=%u, sector=%u, offset=%u, byte_to_sector=%u, inode_left= %u, sector_left=%u\n", size, inode->sector, offset, sector_idx, inode_left, sector_left);
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      struct cache_block * temp_curr_block;
      temp_curr_block = cache_shared_pre(sector_idx);
      bounce = temp_curr_block->data;
      memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      cache_shared_post(temp_curr_block, 0);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  char *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
  // printf("write call: inode_sector=%u, size=%u\n", inode->sector, size);
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      if (sector_idx == UNALLOCATED_SECTOR)
        break;
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      // printf("write: size=%u, sector=%u, offset=%u, byte_to_sector=%u, sector_left=%u\n", size, inode->sector, offset, sector_idx, sector_left);
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;
      
      struct cache_block * temp_curr_block;
      temp_curr_block = cache_shared_pre(sector_idx);
      bounce = temp_curr_block->data;
      memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_shared_post(temp_curr_block, 1);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
    if (offset + size > inode_length(inode)) {
      struct cache_block * inode_block = cache_shared_pre(inode->sector);
      struct inode_disk *disk_inode = (struct inode_disk *) inode_block->data;
      disk_inode->length = offset + size;
      cache_shared_post(inode_block, 1);
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct cache_block * temp_curr_block = cache_shared_pre(inode->sector);
  struct inode_disk *disk_inode = (struct inode_disk *) temp_curr_block->data;
  off_t length = disk_inode->length;
  cache_shared_post(temp_curr_block, 0);
  return length;
}


/* Returns true of this inode corresponds to a directory */
bool inode_isdir (const struct inode *inode) {
  struct cache_block * temp_curr_block = cache_shared_pre(inode->sector);
  struct inode_disk *disk_inode = (struct inode_disk *) temp_curr_block->data;
  uint32_t is_dir = disk_inode->is_dir;
  cache_shared_post(temp_curr_block, 0);
  if (is_dir) {
    return true;
  } else {
    return false;
  }
}
