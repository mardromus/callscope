/* hashmap.h - string-keyed open-addressing hash map (FNV-1a, linear probing). */
#ifndef CALLSCOPE_HASHMAP_H
#define CALLSCOPE_HASHMAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_hm_entry {
    char *key; /* owned copy, NULL when the slot is empty */
    void *val;
    uint64_t hash;
} cs_hm_entry;

typedef struct cs_hashmap {
    cs_hm_entry *entries;
    size_t cap; /* power of two */
    size_t len;
} cs_hashmap;

uint64_t cs_hash_str(const char *s);

void cs_hm_init(cs_hashmap *m);
/* Free all keys; when free_val is non-NULL it is called on every value. */
void cs_hm_free(cs_hashmap *m, void (*free_val)(void *));
void *cs_hm_get(const cs_hashmap *m, const char *key);
/* Insert or replace. Returns 0 on success. */
int cs_hm_put(cs_hashmap *m, const char *key, void *val);
/* Find or insert key and return the address of its value slot (NULL on OOM).
 * A freshly inserted slot holds NULL. The address is valid until the next insert. */
void **cs_hm_slot(cs_hashmap *m, const char *key);
/* Return the stored copy of key (useful for string interning), or NULL. */
const char *cs_hm_key(const cs_hashmap *m, const char *key);

/* Iterate: for (size_t i = 0; cs_hm_next(m, &i, &e);) { ... } */
int cs_hm_next(const cs_hashmap *m, size_t *iter, cs_hm_entry **out);

#ifdef __cplusplus
}
#endif
#endif
