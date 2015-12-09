#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct cache_block
{
	struct list_elem elem;
	block_sector_t sect;
	char dirty; /* If dirty, write back to disk before eviction */
	char valid; /* Indicates whether block is valid */
	uint32_t readers; /* Can have multiple readers */
	uint32_t writers; /* Should only have 1 writer */
	uint32_t write_penders; /* Writers waiting to write */
	uint32_t evict_penders;
	struct lock modify_variables;
	struct condition need_to_write;
	struct condition need_to_evict;
	char use; /* Indicates whether block has been used recently */
	char data[0];
};

// Initializes cache including a bitmap that makes finding unused cache entries easy
void cache_init(void);

void cache_find_block(struct cache_block * curr_block, block_sector_t sect);

void cache_evict_block(struct cache_block* curr_block, block_sector_t sect);

struct cache_block * cache_read_pre(block_sector_t sect);

void cache_read_post(struct cache_block *);

struct cache_block * cache_write_pre(block_sector_t sect);

void cache_write_post(struct cache_block *);

void cache_write_back_on_shutdown(void);
