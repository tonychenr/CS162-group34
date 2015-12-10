#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct cache_block
{
	struct list_elem elem;               /* Cache is a linked list of cache_block elements */
	block_sector_t sect;                 /* Sector of this cache block's data */
	uint8_t dirty;                       /* If dirty, write back to disk before eviction */
	uint8_t valid;                       /* Indicates whether block is valid */
	uint32_t accessors;                  /* Can have multiple readers and writers */
	uint32_t evict_penders;              /* Can have 1 evictor */
	struct lock modify_variables;        /* Lock for meta data */
	struct condition need_to_evict;      /* Monitor for evicting thread */
	uint8_t use;                         /* Indicates whether block has been used recently */
	char data[0];                        /* Address for beginning of data */
};

// Initializes cache including a bitmap that makes finding unused cache entries easy
void cache_init(void);

struct cache_block *cache_find_block(block_sector_t sect);

struct cache_block *cache_evict_block(block_sector_t sect);

struct cache_block *cache_shared_pre(block_sector_t sect);

void cache_shared_post(struct cache_block *, uint8_t dirty);

// struct cache_block * cache_write_pre(block_sector_t sect);

// void cache_write_post(struct cache_block *);

void cache_write_back_on_shutdown(void);

void cache_invalidate_block(block_sector_t sector);
