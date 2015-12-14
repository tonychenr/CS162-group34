#include "threads/synch.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include <list.h>
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "devices/block.h"
#include "threads/malloc.h"



// The "buffer cache" object (list of cache blocks)
static struct cache_block cache[64];

// This lock needs to be acquired in order to evict from the cache
static struct lock eviction_lock;

// Used to implement the clock algorithm
static uint32_t clock_hand;

static int cache_hits;

static int device_writes;

void cache_init(void) 
{
    cache_hits = 0;
    device_writes = 0;
    lock_init(&eviction_lock);
    // Create 64 entries in the buffer cache
    int i;
    for (i = 0; i < 64; i++) 
    {
        struct cache_block *curr_block = &cache[i];
        memset(curr_block->data, 0, BLOCK_SECTOR_SIZE);
        curr_block->dirty = 0;
        curr_block->valid = 0;
        curr_block->accessors = 0;
        curr_block->evict_penders = 0;
        lock_init(&curr_block->modify_variables);
        cond_init(&curr_block->need_to_evict);
        curr_block->use = 0;
    }
    clock_hand = 0;
}

// For testing purposes (lock not acquired because called inside interrupt handler)
void cache_reset(void) {
    struct cache_block *curr_block = NULL;
    int i;
    for (i = 0; i < 64; i++) {
        curr_block = &cache[i];
        curr_block->dirty = 0;
        curr_block->valid = 0;
        curr_block->use = 0;
        curr_block->accessors = 0;
        curr_block->evict_penders = 0;
    }
    cache_hits = 0;
    device_writes = 0;
}

int cache_hits_return(void) {
    return cache_hits;
}

int cache_device_writes(void) {
    return device_writes;
}

/* 
    If curr_block is in the cache, this function locates and returns the block. Return NULL otherwise
    THIS FUNCTION RETURNS POSSESSING AN ENTRIES LOCK
*/
struct cache_block *cache_find_block(block_sector_t sect)
{
    struct cache_block * curr_block = NULL;
    int i;
    for (i = 0; i < 64; i++) {
        curr_block = &cache[i];
        lock_acquire(&curr_block->modify_variables);
        if (curr_block->sect == sect && curr_block->valid) {
            cache_hits++;
            break;
        }
        lock_release(&curr_block->modify_variables);
        curr_block = NULL;
    }
    return curr_block;
}

struct cache_block * cache_evict_block(block_sector_t sect) 
{
    lock_acquire(&eviction_lock);
    struct cache_block * curr_block = cache_find_block(sect);
    if (curr_block == NULL) {
        while (true) {
            if (clock_hand == 64) {
                clock_hand = 0;
            }
            curr_block = &cache[clock_hand];
            lock_acquire(&curr_block->modify_variables);
            if (curr_block->use && curr_block->valid) {
                curr_block->use = 0;
                lock_release(&curr_block->modify_variables);
                clock_hand++;
            } else {
                clock_hand++;
                break;
            }
        }
        // At this point we found an entry to evict and the process owns its modify_variables lock and it has been marked invalid
        curr_block->evict_penders++;
        while (curr_block->accessors > 0) {
            cond_wait(&curr_block->need_to_evict, &curr_block->modify_variables);
        }
        curr_block->evict_penders--;
        if (curr_block->dirty && curr_block->valid) {
            curr_block->valid = 0;
            device_writes++;
            block_write(fs_device, curr_block->sect, curr_block->data);
            // cache_to_disk(curr_block); ACQUIRING LOCK NOT NECESSARY
            curr_block->dirty = 0;
        }
        // Read directly into the cache without the lock since nothing can modify this entry due to it being invalid 
        // Should not be a sychronization problem
        block_read(fs_device, sect, curr_block->data);
        curr_block->sect = sect;
        curr_block->valid = 1;
        curr_block->use = 0;
    }
    lock_release(&eviction_lock);
    return curr_block;
}
    
struct cache_block * cache_shared_pre(block_sector_t sect) {
    struct cache_block* curr_block = cache_find_block(sect);
    if (curr_block == NULL) {
        // eviction needs to occurs
        curr_block = cache_evict_block(sect);
    }
    // Block has been found valid in the cache and this process now owns the entries lock
    curr_block->accessors++;
    lock_release(&curr_block->modify_variables);
    return curr_block;
}

void cache_shared_post(struct cache_block * curr_block, uint8_t dirty) {
    lock_acquire(&curr_block->modify_variables);
    curr_block->accessors--;
    curr_block->use = 1;
    if (dirty) {
        curr_block->dirty = dirty;
    }
    cond_signal(&curr_block->need_to_evict, &curr_block->modify_variables);
    lock_release(&curr_block->modify_variables);
}

/* Iterates through all cache entries, checks if an entry is valid and dirty,
and writes the state to disk. */
void cache_write_back_on_shutdown(void) {
    int i;
    struct cache_block * curr_block;
    for (i = 0; i < 64; i++) {
        curr_block = &cache[i];
        lock_acquire(&curr_block->modify_variables);
        curr_block->evict_penders++;
        while (curr_block->accessors > 0) {
            cond_wait(&curr_block->need_to_evict, &curr_block->modify_variables);
        }
        curr_block->evict_penders--;
        if (curr_block->valid && curr_block->dirty) {
            block_write(fs_device, curr_block->sect, curr_block->data);
        }
        lock_release(&curr_block->modify_variables);
    }
}

void cache_invalidate_block(block_sector_t sector) {
    struct cache_block * curr_block = cache_find_block(sector);
    if (curr_block != NULL) {
        curr_block->valid = 0;
        lock_release(&curr_block->modify_variables);
    }
}

