#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct cache_block
{
    block_sector_t sect;                 /* Sector of this cache block's data */
    uint8_t dirty;                       /* If dirty, write back to disk before eviction */
    uint8_t valid;                       /* Indicates whether block is valid */
    uint32_t accessors;                  /* Can have multiple readers and writers */
    uint32_t evict_penders;              /* Can have 1 evictor */
    struct lock modify_variables;        /* Lock for meta data */
    struct condition need_to_evict;      /* Monitor for evicting thread */
    uint8_t use;                         /* Indicates whether block has been used recently */
    uint8_t data[BLOCK_SECTOR_SIZE];     /* Address for beginning of data */
};

// Initializes cache including a bitmap that makes finding unused cache entries easy
void cache_init(void);

void cache_reset(void);

int cache_hits_return(void);

struct cache_block *cache_find_block(block_sector_t sect);

struct cache_block *cache_evict_block(block_sector_t sect);

struct cache_block *cache_shared_pre(block_sector_t sect);

void cache_shared_post(struct cache_block *, uint8_t dirty);

int cache_device_writes(void);

void cache_write_back_on_shutdown(void);

void cache_invalidate_block(block_sector_t sector);
