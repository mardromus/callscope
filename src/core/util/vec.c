#include "callscope/vec.h"

#include <stdlib.h>
#include <string.h>

void cs_vec_init(cs_vec *v, size_t elem_size) {
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
    v->elem = elem_size;
}

void cs_vec_free(cs_vec *v) {
    free(v->data);
    v->data = NULL;
    v->len = v->cap = 0;
}

void cs_vec_clear(cs_vec *v) { v->len = 0; }

int cs_vec_reserve(cs_vec *v, size_t n) {
    if (n <= v->cap) return 0;
    size_t cap = v->cap ? v->cap : 16;
    while (cap < n) cap *= 2;
    void *p = realloc(v->data, cap * v->elem);
    if (!p) return -1;
    v->data = p;
    v->cap = cap;
    return 0;
}

int cs_vec_push(cs_vec *v, const void *elem) {
    if (cs_vec_reserve(v, v->len + 1) != 0) return -1;
    memcpy((char *)v->data + v->len * v->elem, elem, v->elem);
    v->len++;
    return 0;
}

void *cs_vec_push_slot(cs_vec *v) {
    if (cs_vec_reserve(v, v->len + 1) != 0) return NULL;
    void *slot = (char *)v->data + v->len * v->elem;
    memset(slot, 0, v->elem);
    v->len++;
    return slot;
}

void *cs_vec_at(const cs_vec *v, size_t i) {
    if (i >= v->len) return NULL;
    return (char *)v->data + i * v->elem;
}

void *cs_vec_back(const cs_vec *v) { return v->len ? cs_vec_at(v, v->len - 1) : NULL; }

void cs_vec_pop(cs_vec *v) {
    if (v->len) v->len--;
}

void cs_vec_sort(cs_vec *v, int (*cmp)(const void *, const void *)) {
    if (v->len > 1) qsort(v->data, v->len, v->elem, cmp);
}
