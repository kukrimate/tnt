/*
 * HTTP client
 * Author: Mate Kukri
 * License: ISC
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "dynarr.h"
#include "http.h"

/*
 * Create a "stripped" duplicate of a string
 */
static char *strstrip(char *s, size_t n)
{
	char *start, *end;

	for (start = s; start < s + n; ++start)
		if (!isspace(*start))
			break;
	for (end = s + n - 1; end >= start; --end)
		if (!isspace(*end))
			break;

	return strndup(start, end - start + 1);
}

int http_recieve(int sock, dynarr *resp)
{
	char buf[4096];
	ssize_t len;
	char *bptr;	/* Current position in the buffer */
	char lchr;	/* The last character saved */
	dynarr tmp;
	int state;	/* Current message state: 0-2: Parts of the first line
										  3-4: Name and value of a header */
	size_t i;

	dynarr_new(&tmp, sizeof(char));
	state = 0;

	lchr = 0;
	while (0 < (len = read(sock, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; lchr = *bptr, ++bptr) {
			/* Append to temporary buffer */
			dynarr_addc(&tmp, *bptr);

			switch (*bptr) {
			/* Transition from 0 to 1, or from 1 to 2 */
			case ' ':
				switch (state) {
				case 0:
				case 1:
					dynarr_addp(resp,
						strstrip(tmp.buffer, tmp.elem_count - 1));
					tmp.elem_count = 0;
					++state;
					break;
				}
				break;

			/* Transition from 2 to 3, or from 4 to 3 */
			case '\n':
			 	/* HTTP spec uses CRLF */
				if (lchr != '\r')
					continue;
				switch (state) {
				case 2:
					dynarr_addp(resp,
						strstrip(tmp.buffer, tmp.elem_count - 2));
					tmp.elem_count = 0;
					++state;
					break;
				case 4:
					dynarr_addp(resp,
						strstrip(tmp.buffer, tmp.elem_count - 2));
					tmp.elem_count = 0;
					--state;
					break;
				/* Message ends by empty header */
				case 3:
					if (tmp.elem_count == 2)
						goto success;

				/* CRLF in any other state means a malformed message */
				default:
					goto fail;
				}
				break;

			/* Transition from 3 to 4 */
			case ':':
				switch (state) {
				case 3:
					dynarr_addp(resp,
						strstrip(tmp.buffer, tmp.elem_count - 1));
					tmp.elem_count = 0;
					++state;
					break;
				}
				break;
			}
		}

fail:
	if (-1 == len)
		perror("read");
	else
		fprintf(stderr, "Malformed HTTP response\n");

	for (i = 0; i < resp->elem_count; ++i)
		free(dynarr_getp(resp, i));
	resp->elem_count = 0;
	dynarr_del(&tmp);
	return -1;

success:
	dynarr_del(&tmp);
	return 0;
}

int http_send(int sock, dynarr *req)
{
	size_t i;

	if (0 > dprintf(sock, "%s %s %s\r\n",
				(char *) dynarr_getp(req, 0),
				(char *) dynarr_getp(req, 1),
				(char *) dynarr_getp(req, 2)))
		goto err_write;
	for (i = 3; i < req->elem_count; i += 2) {
		if (0 > dprintf(sock, "%s: %s\r\n",
					(char *) dynarr_getp(req, i),
					(char *) dynarr_getp(req, i + 1)))
			goto err_write;
	}
	if (0 > dprintf(sock, "\r\n"))
		goto err_write;

	return 0;
err_write:
	perror("write");
	return -1;
}
