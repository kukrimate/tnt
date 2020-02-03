#ifndef HTAB_H
#define HTAB_H

typedef struct helem helem;
struct helem {
	char  *key;
	char  *val;
	helem *nex;
};

typedef struct {
	/* # of used buckets */
	size_t used_count;
	/* # of buckets */
	size_t bucket_count;
	/* buffer */
	helem **buffer;
} htab;


/*
 * Create a new hashtable with n preallocated buckets
 */
void htab_new(htab *x, size_t n);

/*
 * Delete a hashtable freeing all memory used, if d is set
 * than key/values will also be free'd
 */
void htab_del(htab *x, int d);

/*
 * Insert a key/value pair into a hashtable, if d is set
 * than key/values will be free'd before overwriting
 */
void htab_put(htab *x, char *key, char *val, int d);

/*
 * Retrieve a value mapped to a given key,
 * if the key is not in the table NULL is returned
 */
char *htab_get(htab *x, char *key);

#endif
