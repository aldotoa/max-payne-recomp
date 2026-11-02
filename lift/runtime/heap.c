/* The guest heap in C (H44): the allocator of emu/mpemu.py (Emu.alloc / Emu.free, FreeList) with the same block
 * choices, so a run gets the same addresses whichever side allocates.
 *
 * - Live blocks: address -> (size, cap). cap is the 16-byte rounded capacity of an alloc() block; 0 marks a block that
 *   only records a size (VirtualAlloc), which free() ignores.
 * - Free blocks: address-ordered by (start, end) maps, coalesced with their neighbours, and in size classes (bit length
 *   of the size). take(n) looks at the class of n and up, and takes the lowest-addressed block that fits in the first
 *   class that has one; the rest of the block stays free.
 * - Fresh memory comes from a bump pointer (next) up to limit.
 *
 * Python owns the heap until the fast path starts (emu/native.py enable_fast): it then copies its state here
 * (lift_heap_reset, lift_heap_set_live, lift_heap_add_free) and Emu.alloc/free call in through ctypes. Calls from lifted
 * code to KERNEL32 HeapAlloc/HeapFree are served here without Python (runtime.c hle_direct -> lift_heap_direct). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "runtime.h"

/* ---- uint32 -> uint64 hash map, open addressing, linear probing, backward-shift deletion. Key 0 is "empty" (no
 * guest heap address is 0). */
typedef struct {
    uint32_t *key;
    uint64_t *val;
    uint32_t mask, n;
} Map;

static uint32_t map_hash(uint32_t k) { return (k >> 4) * 0x9E3779B1u; }

static void map_init(Map *m, uint32_t cap)
{
    free(m->key);
    free(m->val);
    m->key = calloc(cap, sizeof *m->key);
    m->val = calloc(cap, sizeof *m->val);
    m->mask = cap - 1;
    m->n = 0;
}

static uint32_t map_slot(const Map *m, uint32_t k)
{
    uint32_t i = map_hash(k) & m->mask;
    while (m->key[i] && m->key[i] != k)
        i = (i + 1) & m->mask;
    return i;
}

static int map_get(const Map *m, uint32_t k, uint64_t *v)
{
    uint32_t i = map_slot(m, k);
    if (!m->key[i])
        return 0;
    if (v)
        *v = m->val[i];
    return 1;
}

static void map_put(Map *m, uint32_t k, uint64_t v);

static void map_grow(Map *m)
{
    Map old = *m;
    m->key = NULL;
    m->val = NULL;
    map_init(m, (old.mask + 1) * 2);
    for (uint32_t i = 0; i <= old.mask; i++)
        if (old.key[i])
            map_put(m, old.key[i], old.val[i]);
    free(old.key);
    free(old.val);
}

static void map_put(Map *m, uint32_t k, uint64_t v)
{
    uint32_t i = map_slot(m, k);
    if (!m->key[i]) {
        if ((m->n + 1) * 2 > m->mask + 1) {
            map_grow(m);
            i = map_slot(m, k);
        }
        m->key[i] = k;
        m->n++;
    }
    m->val[i] = v;
}

static int map_del(Map *m, uint32_t k, uint64_t *v)
{
    uint32_t i = map_slot(m, k);
    if (!m->key[i])
        return 0;
    if (v)
        *v = m->val[i];
    m->n--;
    for (uint32_t j = i;;) {                  /* backward shift: move later members of the run into the hole */
        m->key[i] = 0;
        for (;;) {
            j = (j + 1) & m->mask;
            if (!m->key[j])
                return 1;
            uint32_t h = map_hash(m->key[j]) & m->mask;
            if (i <= j ? (i < h && h <= j) : (i < h || h <= j))
                continue;                     /* its home lies after the hole: it stays */
            break;
        }
        m->key[i] = m->key[j];
        m->val[i] = m->val[j];
        i = j;
    }
}

/* ---- free blocks: nodes in per-class doubly linked lists, found by start and by end */
typedef struct {
    uint32_t p, size;
    int32_t prev, next;
} Node;

#define CLASSES 34
static Node *g_nodes;
static int32_t g_nodes_cap, g_nodes_n, g_node_free = -1;
static int32_t g_cls[CLASSES];
static Map g_start, g_end, g_live;           /* start -> node; end -> node; live p -> size | cap << 32 */
static uint64_t g_next, g_limit, g_free_total, g_live_caps;
static uint32_t g_live_capped;               /* live blocks with a cap (alloc() blocks) */
static uint64_t g_direct_alloc, g_direct_free;
static uint32_t g_idx_alloc = UINT32_MAX, g_idx_free = UINT32_MAX;
static int g_heap_on;

static int cls_of(uint32_t size) { return size ? 32 - __builtin_clz(size) : 0; }

static int32_t node_new(void)
{
    if (g_node_free >= 0) {
        int32_t i = g_node_free;
        g_node_free = g_nodes[i].next;
        return i;
    }
    if (g_nodes_n == g_nodes_cap) {
        g_nodes_cap = g_nodes_cap ? g_nodes_cap * 2 : 1024;
        g_nodes = realloc(g_nodes, (size_t)g_nodes_cap * sizeof *g_nodes);
    }
    return g_nodes_n++;
}

static void free_add(uint32_t p, uint32_t size)
{
    int32_t i = node_new();
    int c = cls_of(size);
    g_nodes[i] = (Node){p, size, -1, g_cls[c]};
    if (g_cls[c] >= 0)
        g_nodes[g_cls[c]].prev = i;
    g_cls[c] = i;
    map_put(&g_start, p, (uint64_t)i);
    map_put(&g_end, p + size, (uint64_t)i);
    g_free_total += size;
}

static uint32_t free_remove(int32_t i)
{
    Node *n = &g_nodes[i];
    uint32_t size = n->size;
    if (n->prev >= 0)
        g_nodes[n->prev].next = n->next;
    else
        g_cls[cls_of(size)] = n->next;
    if (n->next >= 0)
        g_nodes[n->next].prev = n->prev;
    map_del(&g_start, n->p, NULL);
    map_del(&g_end, n->p + size, NULL);
    g_free_total -= size;
    n->next = g_node_free;
    g_node_free = i;
    return size;
}

static void free_put(uint32_t p, uint32_t size)      /* FreeList.put */
{
    uint64_t q;
    if (map_get(&g_end, p, &q)) {
        uint32_t qp = g_nodes[q].p;
        size += free_remove((int32_t)q);
        p = qp;
    }
    if (map_get(&g_start, p + size, &q))
        size += free_remove((int32_t)q);
    free_add(p, size);
}

static int free_take(uint32_t size, uint32_t *out)  /* FreeList.take */
{
    for (int c = cls_of(size); c <= 32; c++) {
        int32_t best = -1;
        for (int32_t i = g_cls[c]; i >= 0; i = g_nodes[i].next)
            if (g_nodes[i].size >= size && (best < 0 || g_nodes[i].p < g_nodes[best].p))
                best = i;
        if (best >= 0) {
            uint32_t p = g_nodes[best].p, have = free_remove(best);
            if (have > size)
                free_add(p + size, have - size);
            *out = p;
            return 1;
        }
    }
    return 0;
}

/* ---- the allocator */
void lift_heap_reset(uint64_t next, uint64_t limit)
{
    map_init(&g_start, 1024);
    map_init(&g_end, 1024);
    map_init(&g_live, 4096);
    g_nodes_n = 0;
    g_node_free = -1;
    for (int c = 0; c < CLASSES; c++)
        g_cls[c] = -1;
    g_next = next;
    g_limit = limit;
    g_free_total = g_live_caps = 0;
    g_live_capped = 0;
    g_direct_alloc = g_direct_free = 0;
    g_idx_alloc = g_idx_free = UINT32_MAX;
    g_heap_on = 1;
}

void lift_heap_set_live(uint32_t p, uint32_t size, uint32_t cap)
{
    uint64_t old;
    if (map_get(&g_live, p, &old) && (old >> 32)) {
        g_live_caps -= old >> 32;
        g_live_capped--;
    }
    map_put(&g_live, p, size | (uint64_t)cap << 32);
    if (cap) {
        g_live_caps += cap;
        g_live_capped++;
    }
}

void lift_heap_add_free(uint32_t p, uint32_t size) { free_add(p, size); }

/* Emu.alloc without the zeroing: the block for size bytes (size >= 1), or 0 when the heap is exhausted. *reused is 1
 * for a block from the free list (its memory is not zero), 0 for fresh memory. */
uint32_t lift_heap_alloc(uint32_t size, int *reused)
{
    uint64_t cap = ((uint64_t)size + 15) & ~(uint64_t)15;
    uint32_t p;
    if (cap <= UINT32_MAX && free_take((uint32_t)cap, &p)) {
        *reused = 1;
    } else {
        uint64_t q = (g_next + 15) & ~(uint64_t)15;
        if (q + cap > g_limit)
            return 0;
        g_next = q + cap;
        p = (uint32_t)q;
        *reused = 0;
    }
    lift_heap_set_live(p, size, (uint32_t)cap);
    return p;
}

/* Emu.free: 1 when p was an alloc() block (now free), 0 otherwise (ignored). */
int lift_heap_free(uint32_t p)
{
    uint64_t v;
    if (!p || !map_get(&g_live, p, &v) || !(v >> 32))
        return 0;
    map_del(&g_live, p, NULL);
    g_live_caps -= v >> 32;
    g_live_capped--;
    free_put(p, (uint32_t)(v >> 32));
    return 1;
}

/* Live block of p: 1 and its size and cap (0 for a size-only block), or 0. */
int lift_heap_get(uint32_t p, uint32_t *size, uint32_t *cap)
{
    uint64_t v;
    if (!p || !map_get(&g_live, p, &v))
        return 0;
    *size = (uint32_t)v;
    *cap = (uint32_t)(v >> 32);
    return 1;
}

/* A size-only block of size bytes at the page-aligned bump pointer, recorded when record is set (VirtualAlloc; a
 * file view is not recorded). Not limited, as in Python. */
uint32_t lift_heap_reserve(uint32_t size, int record)
{
    uint64_t p = (g_next + 0xfff) & ~(uint64_t)0xfff;
    uint32_t sz = record ? size : (size ? size : 1);
    g_next = p + (((uint64_t)sz + 0xfff) & ~(uint64_t)0xfff);
    if (record)
        lift_heap_set_live((uint32_t)p, size, 0);
    return (uint32_t)p;
}

uint64_t lift_heap_next(void) { return g_next; }

/* out: next, live blocks, live alloc() blocks, their capacity, free bytes, free blocks, direct HeapAlloc and HeapFree
 * calls (lift_heap_direct). */
void lift_heap_stats(uint64_t *out)
{
    out[0] = g_next;
    out[1] = g_live.n;
    out[2] = g_live_capped;
    out[3] = g_live_caps;
    out[4] = g_free_total;
    out[5] = g_start.n;
    out[6] = g_direct_alloc;
    out[7] = g_direct_free;
}

/* Live blocks as (p, size, cap) triples, up to cap_n of them; returns how many there are. */
uint32_t lift_heap_export_live(uint32_t *out, uint32_t cap_n)
{
    uint32_t k = 0;
    for (uint32_t i = 0; i <= g_live.mask; i++)
        if (g_live.key[i]) {
            if (k < cap_n) {
                out[3 * k] = g_live.key[i];
                out[3 * k + 1] = (uint32_t)g_live.val[i];
                out[3 * k + 2] = (uint32_t)(g_live.val[i] >> 32);
            }
            k++;
        }
    return k;
}

/* Free blocks as (p, size) pairs, as lift_heap_export_live. */
uint32_t lift_heap_export_free(uint32_t *out, uint32_t cap_n)
{
    uint32_t k = 0;
    for (uint32_t i = 0; i <= g_start.mask; i++)
        if (g_start.key[i]) {
            if (k < cap_n) {
                out[2 * k] = g_start.key[i];
                out[2 * k + 1] = g_nodes[g_start.val[i]].size;
            }
            k++;
        }
    return k;
}

/* The HLE stub indexes of KERNEL32 HeapAlloc and HeapFree (UINT32_MAX: none), for lift_heap_direct. */
void lift_heap_direct_bind(uint32_t idx_alloc, uint32_t idx_free)
{
    g_idx_alloc = idx_alloc;
    g_idx_free = idx_free;
}

/* A direct call from lifted code to HLE stub idx (runtime.c hle_direct; the return address is at [esp], the stdcall
 * arguments above it). For HeapAlloc(heap, flags, size) and HeapFree(heap, flags, p), does what the Python handler
 * does through Emu.hle_direct: EAX is the result, ESP pops the frame, and a reused block is zeroed. Returns 1 when done,
 * 0 for any other stub or an exhausted heap (Python then raises as before). */
int lift_heap_direct(CPU *c, uint32_t idx)
{
    if (!g_heap_on || (idx != g_idx_alloc && idx != g_idx_free))
        return 0;
    uint32_t sp = c->r[ESP], arg = rd32(c, sp + 12);
    if (idx == g_idx_alloc) {
        int reused;
        uint32_t size = arg ? arg : 1, p = lift_heap_alloc(size, &reused);
        if (!p)
            return 0;
        if (reused) {
            size_t cap = ((size_t)size + 15) & ~(size_t)15;
            NOTE_WRITE(c, p, cap);
            memset(MEM(c, p), 0, cap);
        }
        c->r[EAX] = p;
        g_direct_alloc++;
    } else {
        lift_heap_free(arg);
        c->r[EAX] = 1;
        g_direct_free++;
    }
    c->r[ESP] = sp + 16;
    return 1;
}
