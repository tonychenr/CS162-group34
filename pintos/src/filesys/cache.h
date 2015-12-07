#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct cache_block
{
	struct list_elem elem;
	block_sector_t sect;
	char dirty;
	char valid;
	uint32_t readers;
	uint32_t writers;
	uint32_t evict_penders;
	struct lock modify_variables;
	struct condition need_to_write;
	struct condition need_to_evict;
	char use;
	struct inode *inode;
	uint8_t *data;
};

// Initializes cache including a bitmap that makes finding unused cache entries easy
void cache_init(void);

void cache_find_block(struct cache_block * curr_block, struct inode * inode, block_sector_t sect);

void cache_evict_block(struct cache_block* curr_block, struct inode* inode, block_sector_t sect);

struct cache_block * cache_read_pre(struct inode * inode, block_sector_t sect);

void cache_read_post(struct cache_block *);

struct cache_block * cache_write_pre(struct inode * inode, block_sector_t sect);

void cache_write_post(struct cache_block *);

void cache_write_back_on_shutdown(void);
