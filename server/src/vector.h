#ifndef VECTOR_H
#define VECTOR_H

#include <stdlib.h>

typedef struct vec *vec_t;

vec_t vec_new(int (cmp_fn)(const void *a, const void *b));
int vec_size(const vec_t vec);
int vec_add(const vec_t vec, void *elem);
int vec_remove(const vec_t vec, const void *elem);
int vec_contains(const vec_t vec, const void *elem);
void *vec_nth(const vec_t vec, int n);
void *vec_find(const vec_t vec, const void *elem);
void vec_destroy(const vec_t vec, void (free_fn)(void *ptr));
void print_vec(const vec_t vec);

#endif
