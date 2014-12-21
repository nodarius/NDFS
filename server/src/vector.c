#include <string.h>
#include "vector.h"
#include "logger.h"

struct vec {
	int size_a;		/* allocated size */
	int size_l;		/* logical size */
	int (*cmp_fn) (const void *a, const void *b);
	int **elems;
};

vec_t vec_new(int (cmp_fn)(const void *a, const void *b))
{
	vec_t vec = calloc(1, sizeof (struct vec));
	check_mem(vec);
	vec->size_a = 10;
	vec->size_l = 0;
	vec->cmp_fn = cmp_fn;

	vec->elems = calloc(vec->size_a, sizeof (int*));
	check_mem(vec);

	return vec;
}
int vec_size(const vec_t vec)
{
	return vec->size_l;
}
int vec_add(const vec_t vec, void *elem)
{
	if (vec->size_l >= vec->size_a - 1) {
		vec->size_a++;
		vec->size_a *= 2;
		vec->elems = realloc(vec->elems, vec->size_a * sizeof (int*));
		check_mem(vec->elems);
	}

	if (vec_contains(vec, elem)) {
		return 0;
	}
	vec->elems[vec->size_l++] = elem;

	return 1;
}

void print_vec(const vec_t vec)
{
	printf("printing vec----------------------\n");
	printf("vec size: %d - %d\n", vec->size_a, vec->size_l);
	int i;
	for (i = 0; i < vec->size_l; i++) {
		printf("%p | ", vec->elems[i]);
	}
	printf("\n");
}

static int get_index(const vec_t vec, const void *elem)
{
	int i;
	for (i = 0; i < vec->size_l; i++) {
		if (vec->cmp_fn(&elem, &vec->elems[i]) == 0) {
			return i;
		}
	}
	return -1;
}

int vec_remove(const vec_t vec, const void *elem)
{
	int elem_index = get_index(vec, elem);
	if (elem_index == -1) {
		return 0;
	}
	int i;
	for (i = elem_index; i < vec->size_l - 1; i++) {
		vec->elems[i] = vec->elems[i + 1];
	}
	vec->size_l--;
	return 1;
}

void *vec_nth(const vec_t vec, int n)
{
	if (n < 0 || n >= vec->size_l) {
		return NULL;
	}
	return vec->elems[n];
}

int vec_contains(const vec_t vec, const void *elem)
{
	if (vec_find(vec, elem)) {
		return 1;
	}
	return 0;
}

void *vec_find(const vec_t vec, const void *elem)
{
	int i;
	for (i = 0; i < vec->size_l; i++) {
		if (vec->cmp_fn(&elem, &vec->elems[i]) == 0) {
			return vec->elems[i];
		}
	}
	return NULL;
}

void vec_destroy(const vec_t vec, void (free_fn)(void *ptr))
{
	int i;
	for (i = 0; i < vec->size_l; i++) {
		free_fn(vec->elems[i]);
	}
	free(vec->elems);
}
