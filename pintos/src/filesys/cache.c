#include "filesys/cache.h"
#include "filesys/filesys.h"
#include <list.h>
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"


// The "buffer cache" object (list of cache blocks)
static struct list buffer_cache_entries;

// This lock needs to be acquired in order to evict from the cache
static struct lock eviction_lock;

// Used to implement the clock algorithm
static struct list_elem *clock_hand;

void cache_init(void) 
{
	list_init(&buffer_cache_entries);
	lock_init(&eviction_lock);
	clock_hand = list_begin(&buff_cache_entries);
	// Create 64 entries in the buffer cache
	int i;
	for (i = 1; i <= 64; i++) 
	{
		struct cache_block * curr_block = malloc(sizeof(struct cache_block));
		curr_block->data = malloc(BUFFER_SECTOR_SIZE);
		curr_block->dirty = 0;
		curr_block->valid = 0;
		curr_block->readers = 0;
		curr_block->writers = 0;
		curr_block->evict_penders = 0;
		lock_init(&curr_block->modify_variables);
		condition_init(&curr_block->need_to_write);
		condition_init(&curr_block->need_to_evict);
		curr_block->use = 0;
		list_push_back(&buff_cache_entries, &curr_block->elem);
	}
}

/* 
	If curr_block is in the cache, this function locates and returns the block. Return NULL otherwise
	THIS FUNCTION RETURNS POSSESSING AN ENTRIES LOCK
*/
void cache_find_block(struct cache_block * curr_block, struct inode * inode, 
										block_sector_t sect)
{
	struct list_elem* e;
	e = list_begin(&buffer_cache_entries);
	while (true) {
		curr_block = list_entry(e, struct cache_block, elem);
		if (curr_block->inode == inode && curr_block->sect == sect) {
 			lock_acquire(&curr_block->modify_variables);
 			if (curr_block->inode == inode && curr_block_>sect == sect && curr_block->valid) {
 				break;
 			}
 			lock_release(&curr_block->modify_variables);
 		}
 		e = list_next(e);
 		curr_block = NULL;
	}
}

void cache_evict_block(struct cache_block* curr_block, struct inode* inode, block_sector_t sect) 
{
	lock_acquire(&eviction_lock);
	cache_find_block(curr_block, inode, sect);
	if (curr_block == NULL) {
		while (true) {
			curr_block = list_entry(clock_hand, struct cache_block, elem);
			if (curr_block->use) {
				lock_acquire(&curr_block->modify_variables);
				curr_block->use = 0;
				lock_release(&curr_block->modify_variables);
				clock_hand = list_next(clock_hand);
			} else {
				lock_acquire(&curr_block->modify_variables);
				if (curr_block->use == 0) {
					curr_block->valid = 0;
					clock_hand = list_next(clock_hand);
					break
				} else {
					// Changed between acquiring the lock and checking the first time
					lock_release(&curr_block->modify_variables);
					clock_hand = list_next(clock_hand);
				}
			}
		}
		// At this point we found an entry to evict and the process owns its modify_variables lock and it has been marked invalid
		if (readers != 0 || writers != 0) {
			curr_block->evict_penders++;
			cond_wait(&curr_block->need_to_evict, &curr_block->modify_variables);
			curr_block->evict_penders--;
		}
		if (curr_block->dirty) { 
			lock_release(&curr_block->modify_variables);
			block_write(fs_device, curr_block->sect, curr_block->data);
			// cache_to_disk(curr_block); ACQUIRING LOCK NOT NECESSARY
			lock_acquire(&curr_block->modify_variables);
			curr_block->dirty = 0;
		}
		lock_release(&curr_block->modify_variables);
		// Read directly into the cache without the lock since nothing can modify this entry due to it being invalid 
		// Should not be a sychronization problem
		block_read(fs_device, sect, curr_block->data);
		lock_acquire(&curr_block->modify_variables);
		curr_block->inode = inode;
		curr_block->sect = sect;
		curr_block->data = buffer;
		curr_block->valid = 1;
	}
	lock_release(&eviction_lock);
}
	
struct cache_block * cache_read_pre(struct inode * inode, block_sector_t sect) {
	struct cache_block* curr_block;
	uint8_t * ret_data;
	cache_find_block(curr_block, inode, sect);
	if (curr_block == NULL) {
		// eviction needs to occurs
		cache_evict_block(curr_block, inode, sect);
	}
	// Block has been found valid in the cache and this process now owns the entries lock
	curr_block->readers++;
	lock_release(&curr_block->modify_variables);
	return curr_block;
}

void cache_read_post(struct cache_block * curr_block) {
	lock_acquire(&curr_block->modify_variables);
	curr_block->readers--;
	curr_block->use = 1;
	if (curr_block->readers == 0 && curr_block->writers == 0 && curr_block->evict_penders > 0) {
		cond_signal(&need_to_evict, &modify_variables);
	}
	lock_release(&curr_block->modify_variables);
}



struct cache_block * cache_write_pre(struct inode * inode, block_sector_t sect) {
	struct cache_block* curr_block;
	uint8_t ret_data;
	cache_find_block(curr_block, inode, sect);
	if (curr_block == NULL) {
		cache_evict_block(curr_block, inode, sect);
	}
	// Block has been found valid in the cache and this process now owns the entires lock
	if (curr_block->writers > 0) {
		cond_wait(&curr_block->need_to_write , &curr_block->modify_variables);
	}
	curr_block->writers++;
	lock_release(&curr_block->modify_variables);
	return curr_block;
}

void cache_write_post(struct cache_block* curr_block) {
	lock_acquire(&curr_block->modify_variables);
	curr_block->writers--;
	curr_block->use = 1;
	curr_block->dirty = 1;
	if (curr_block->writers > 0) {
		cond_signal(&need_to_write, &modify_variables);
	} else if (curr_block->readers == 0 && curr_block->writers == 0 && curr_block->evict_penders > 0) {
		cond_signal(&need_to_evict, &modify_variables);
	}
	lock_release(&curr_block->modify_variables);
}

/* Iterates through all cache entries, checks if an entry is valid and dirty,
and writes the state to disk. */
void cache_write_back_on_shutdown(void) {
	struct list_elem* e;
	e = list_begin(&buffer_cache_entries);
	int count = 1;
	while (counter <= 64) {
		curr_block = list_entry(e, struct cache_block, elem);
		lock_acquire(&curr_block->modify_variables);
		if (curr_block->writers > 0) {
			cond_wait(&curr_block->need_to_write);
		}
		curr_block->writers++;
		if (curr_block->valid && curr_block->dirty) {
			lock_release(&curr_block->modify_variables);
			block_write(fs_device, curr_block->sect, curr_block->data);
 		}
 		e = list_next(e);
 		count++;
	}
}
