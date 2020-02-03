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
#include <arpa/inet.h>
#include "dynarr.h"
#include "htab.h"
#include "url.h"
#include "conn.h"
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

typedef enum {
	VERSION = 0,
	STATUS  = 1,
	REASON  = 2,
	HDR_NAM = 3,
	HDR_VAL = 4
} http_resp_state;

int http_recieve(conn *conn, http_response *resp, size_t *consumed)
{
	ssize_t len;
	char buf[4096];

	char lchr;	/* Last character */
	char *bptr;	/* Current character */

	char *hdr_nam; /* Current header name */

	dynarr tmp;
	http_resp_state state;

	bzero(resp, sizeof(http_response));
	htab_new(&resp->headers, 100);
	hdr_nam = NULL;

	dynarr_new(&tmp, sizeof(char));
	state = VERSION;

	lchr = 0;
	while (0 < (len = conn_read(conn, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; lchr = *bptr, ++bptr) {
			dynarr_addc(&tmp, *bptr);

			switch (*bptr) {
			case ' ':
				switch (state) {
				case VERSION:
					resp->version = strstrip(tmp.buffer, tmp.elem_count - 1);
					tmp.elem_count = 0;
					state = STATUS;
					break;
				case STATUS:
					resp->status = strstrip(tmp.buffer, tmp.elem_count - 1);
					tmp.elem_count = 0;
					state = REASON;
					break;
				default:
					break;
				}
				break;

			case ':':
				switch (state) {
				case HDR_NAM:
					hdr_nam = strstrip(tmp.buffer, tmp.elem_count - 1);
					tmp.elem_count = 0;
					state = HDR_VAL;
					break;
				default:
					break;
				}
				break;

			case '\n':
				/* HTTP spec uses CRLF */
				if (lchr != '\r')
					continue;

				switch (state) {
				case REASON:
					resp->reason = strstrip(tmp.buffer, tmp.elem_count - 1);
					tmp.elem_count = 0;
					state = HDR_NAM;
					break;
				case HDR_VAL:
					htab_put(&resp->headers, hdr_nam,
						strstrip(tmp.buffer, tmp.elem_count - 2), 1);
					hdr_nam = NULL;
					tmp.elem_count = 0;
					state = HDR_NAM;
					break;

				/* Message ends by empty header */
				case HDR_NAM:
					if (2 == tmp.elem_count)
						goto success;

				/* CRLF in any other state means a malformed message */
				default:
					goto fail;
				}
				break;
			}
		}

fail:
	if (-1 == len)
		conn_perror(conn, "conn_read");
	else
		fprintf(stderr, "http_recieve: Malformed HTTP response\n");

	if (hdr_nam)
		free(hdr_nam);
	if (resp->version)
		free(resp->version);
	if (resp->status)
		free(resp->status);
	if (resp->reason)
		free(resp->reason);
	htab_del(&resp->headers, 1);
	dynarr_del(&tmp);
	return -1;

success:
	*consumed = len - (bptr - buf) - 1;
	dynarr_del(&tmp);
	return 0;
}

int http_send(conn *conn, dynarr *req)
{
	size_t i, l;
	char buffer[4096];

	l = snprintf(buffer, sizeof(buffer), "%s %s %s\r\n",
		(char *) dynarr_getp(req, 0),
		(char *) dynarr_getp(req, 1),
		(char *) dynarr_getp(req, 2));
	if (-1 == conn_write(conn, buffer, l))
		goto err_write;

	for (i = 3; i < req->elem_count; i += 2) {
		l = snprintf(buffer, sizeof(buffer), "%s: %s\r\n",
			(char *) dynarr_getp(req, i),
			(char *) dynarr_getp(req, i + 1));
		if (-1 == conn_write(conn, buffer, l))
			goto err_write;
	}
	if (-1 == conn_write(conn, "\r\n", 2))
		goto err_write;

	return 0;
err_write:
	conn_perror(conn, "conn_write");
	return -1;
}
