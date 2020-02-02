#ifndef DYNARR_H
#define DYNARR_H

typedef struct{
	/* element size */
	size_t elem_size;
	/* # of elements */
	size_t elem_count;
	/* buffer size in bytes */
	size_t buffer_size;
	/* buffer */
	void *buffer;
} dynarr;

/*
 * Create a new dynamic array in x with an element size of elem_size
 */
void dynarr_new(dynarr *x, size_t elem_size);

/*
 * Delete a dynamic array x
 */
void dynarr_del(dynarr *x);

/*
 * Delete a dynamix array x and free all elements
 */
void dynarr_delall(dynarr *x);


/*
 * Append cnt new elements to dynarmic array x
 */
void dynarr_add(dynarr *x, size_t cnt, void *d);

/*
 * Append a character c to dynamic array x
 */
void dynarr_addc(dynarr *x, char c);

/*
 * Append a pointer p to dynamic array x
 */
void dynarr_addp(dynarr *x, void *p);


/*
 * Pointer to the ith element
 */
void *dynarr_ptr(dynarr *x, size_t i);

/*
 * Get cnt elements starting from the i-th from dynamic array x
 */
void dynarr_get(dynarr *x, size_t i, size_t cnt, void *d);

/*
 * Get the nth character from dynamic array x
 */
char dynarr_getc(dynarr *x, size_t i);

/*
 * Get the nth pointer from dynamic array x
 */
void *dynarr_getp(dynarr *x, size_t i);

#endif
