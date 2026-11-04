#include "callscope/hashmap.h"

#include <stdlib.h>
#include <string.h>

uint64_t cs_hash_str(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

void cs_hm_init(cs_hashmap *m) {
    m->entries = NULL;
    m->cap = 0;
    m->len = 0;
}

void cs_hm_free(cs_hashmap *m, void (*free_val)(void *)) {
    for (size_t i = 0; i < m->cap; i++) {
        if (m->entries[i].key) {
            free(m->entries[i].key);
            if (free_val) free_val(m->entries[i].val);
        }
    }
    free(m->entries);
    cs_hm_init(m);
}

static cs_hm_entry *find(const cs_hashmap *m, const char *key, uint64_t h) {
    if (!m->cap) return NULL;
    size_t mask = m->cap - 1;
    for (size_t i = h & mask;; i = (i + 1) & mask) {
        cs_hm_entry *e = &m->entries[i];
        if (!e->key) return e;
        if (e->hash == h && strcmp(e->key, key) == 0) return e;
    }
}

static int grow(cs_hashmap *m) {
    size_t ncap = m->cap ? m->cap * 2 : 64;
    cs_hm_entry *ne = calloc(ncap, sizeof(*ne));
    if (!ne) return -1;
    for (size_t i = 0; i < m->cap; i++) {
        cs_hm_entry *e = &m->entries[i];
        if (!e->key) continue;
        size_t j = e->hash & (ncap - 1);
        while (ne[j].key) j = (j + 1) & (ncap - 1);
        ne[j] = *e;
    }
    free(m->entries);
    m->entries = ne;
    m->cap = ncap;
    return 0;
}

void *cs_hm_get(const cs_hashmap *m, const char *key) {
    cs_hm_entry *e = find(m, key, cs_hash_str(key));
    return (e && e->key) ? e->val : NULL;
}

const char *cs_hm_key(const cs_hashmap *m, const char *key) {
    cs_hm_entry *e = find(m, key, cs_hash_str(key));
    return (e && e->key) ? e->key : NULL;
}

void **cs_hm_slot(cs_hashmap *m, const char *key) {
    uint64_t h = cs_hash_str(key);
    cs_hm_entry *e = find(m, key, h);
    if (e && e->key) return &e->val;
    if ((m->len + 1) * 4 > m->cap * 3) { /* keep load factor under 0.75 */
        if (grow(m) != 0) return NULL;
        e = find(m, key, h);
    }
    size_t klen = strlen(key);
    e->key = malloc(klen + 1);
    if (!e->key) return NULL;
    memcpy(e->key, key, klen + 1);
    e->hash = h;
    e->val = NULL;
    m->len++;
    return &e->val;
}

int cs_hm_put(cs_hashmap *m, const char *key, void *val) {
    void **slot = cs_hm_slot(m, key);
    if (!slot) return -1;
    *slot = val;
    return 0;
}

int cs_hm_next(const cs_hashmap *m, size_t *iter, cs_hm_entry **out) {
    while (*iter < m->cap) {
        cs_hm_entry *e = &m->entries[(*iter)++];
        if (e->key) {
            *out = e;
            return 1;
        }
    }
    return 0;
}
