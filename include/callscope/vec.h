/* vec.h - type-erased growable array. Elements are stored inline. */
#ifndef CALLSCOPE_VEC_H
#define CALLSCOPE_VEC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_vec {
    void *data;
    size_t len;
    size_t cap;
    size_t elem; /* size of one element in bytes */
} cs_vec;

void cs_vec_init(cs_vec *v, size_t elem_size);
void cs_vec_free(cs_vec *v);
void cs_vec_clear(cs_vec *v);
int cs_vec_reserve(cs_vec *v, size_t n);
/* Copy *elem into the vector. Returns 0 on success. */
int cs_vec_push(cs_vec *v, const void *elem);
/* Append a zero-initialised element and return a pointer to it (NULL on OOM).
 * The pointer is invalidated by the next push. */
void *cs_vec_push_slot(cs_vec *v);
void *cs_vec_at(const cs_vec *v, size_t i);
void *cs_vec_back(const cs_vec *v);
void cs_vec_pop(cs_vec *v);
void cs_vec_sort(cs_vec *v, int (*cmp)(const void *, const void *));

#define CS_VEC_AT(v, T, i) ((T *)cs_vec_at((v), (i)))

#ifdef __cplusplus
}
#endif
#endif
