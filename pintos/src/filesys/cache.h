#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct cache_block;

// Initializes cache including a bitmap that makes finding unused cache entries easy
void cache_init(void);

void cache_find_block(struct cache_block * curr_block, struct inode * inode, block_sector_t sect);

void cache_evict_block(struct cache_block* curr_block, struct inode* inode, block_sector_t sect);

uint8_t * cache_read(struct inode * inode, block_sector_t sect);

uint8_t * cache_write(struct inode * inode, block_sector_t sect);

// void cache_to_disk(struct cache_block* block_writing);
