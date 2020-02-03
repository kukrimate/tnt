/*
 * Hash table using DJB2 and chaining
 * Auhor: Mate Kukri
 * License: ISC
 */
#include <stdlib.h>
#include <string.h>
#include "htab.h"

static size_t djb2_hash(char *str)
{
	size_t r;

	r = 5381;
	for (; *str; ++str)
		r = (r << 5) + r + *str;
	return r;
}

/*
 * Put key/value paris into a hashtable *without* checking for key overwrites
 */
static void htab_putuniq(htab *x, char *key, char *val)
{
	helem **e;

	e = x->buffer + djb2_hash(key) % x->bucket_count;
	if (!*e)
		++x->used_count;
	else
		for (; *e; e = &(*e)->nex);

	*e = malloc(sizeof(helem));
	if (!*e)
		abort();
	(*e)->key = key;
	(*e)->val = val;
	(*e)->nex = NULL;
}

/*
 * "Grow" a hashtable by creating a new one and overwriting it
 */
static void htab_grow(htab *x, size_t n)
{
	htab y;
	helem **b, *e, *t;

	htab_new(&y, n);
	for (b = x->buffer; b < x->buffer + x->bucket_count; ++b)
		for (e = *b; e; ) {
			htab_putuniq(&y, e->key, e->val);
			t = e->nex;
			free(e);
			e = t;
		}
	free(x->buffer);
	*x = y;
}


void htab_new(htab *x, size_t n)
{
	x->used_count   = 0;
	x->bucket_count = n;
	x->buffer       = calloc(n, sizeof(void *));
	if (!x->buffer)
		abort();
}

void htab_del(htab *x, int d)
{
	helem **b, *e, *t;

	for (b = x->buffer; b < x->buffer + x->bucket_count; ++b)
		for (e = *b; e; ) {
			if (d) {
				free(e->key);
				free(e->val);
			}
			t = e->nex;
			free(e);
			e = t;
		}
	free(x->buffer);
}


void htab_put(htab *x, char *key, char *val, int d)
{
	helem **e;

	if (x->used_count > x->bucket_count * 3 / 4)
		htab_grow(x, x->bucket_count * 2);

	e = x->buffer + djb2_hash(key) % x->bucket_count;

	if (!*e)
		++x->used_count;
	else
		for (; *e; e = &(*e)->nex)
			if (!strcmp((*e)->key, key)) {
				if (d) {
					free((*e)->key);
					free((*e)->val);
				}
				goto insert;
			}

	*e = malloc(sizeof(helem));
	if (!*e)
		abort();
	(*e)->nex = NULL;

insert:
	(*e)->key = key;
	(*e)->val = val;
}

char *htab_get(htab *x, char *key)
{
	helem **e;

	e = x->buffer + djb2_hash(key) % x->bucket_count;
	for (; *e; e = &(*e)->nex)
		if (!strcmp((*e)->key, key))
			return (*e)->val;

	return NULL;
}
