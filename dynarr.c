/*
 * Dynamic array implementation
 * Author: Mate Kukri
 * License: ISC
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dynarr.h"

/*
 * Make sure dynamic array x can fit cnt more elements
 */
static void dynarr_grow(dynarr *x, size_t cnt)
{
	size_t needed_size;

	needed_size = (x->elem_count + cnt) * x->elem_size;
	if (x->buffer_size < needed_size) {
		x->buffer_size = needed_size * 2;
		x->buffer = realloc(x->buffer, x->buffer_size);
		if (!x->buffer)
			abort();
	}
}


void dynarr_new(dynarr *x, size_t elem_size)
{
	x->elem_size = elem_size;
	x->elem_count = x->buffer_size = 0;
	x->buffer = NULL;
}

void dynarr_del(dynarr *x)
{
	if (x->buffer)
		free(x->buffer);
}

void dynarr_delall(dynarr *x)
{
	size_t i;

	for (i = 0; i < x->elem_count; ++i)
		free(dynarr_getp(x, i));
	dynarr_del(x);
}


void dynarr_add(dynarr *x, size_t cnt, void *d)
{
	dynarr_grow(x, cnt);
	memcpy((char *) x->buffer + x->elem_count * x->elem_size,
		d, cnt * x->elem_size);
	x->elem_count += cnt;
}

void dynarr_addc(dynarr *x, char c)
{
	dynarr_grow(x, 1);
	((char *) x->buffer)[x->elem_count++] = c;
}

void dynarr_addp(dynarr *x, void *p)
{
	dynarr_grow(x, 1);
	((void **) x->buffer)[x->elem_count++] = p;
}


void *dynarr_ptr(dynarr *x, size_t i)
{
	return (char *) x->buffer + i * x->elem_size;
}

void dynarr_get(dynarr *x, size_t i, size_t cnt, void *d)
{
	memcpy(d, (char *) x->buffer + i * x->elem_size, cnt * x->elem_size);
}

char dynarr_getc(dynarr *x, size_t i)
{
	return ((char *) x->buffer)[i];
}

void *dynarr_getp(dynarr *x, size_t i)
{
	return ((void **) x->buffer)[i];
}
