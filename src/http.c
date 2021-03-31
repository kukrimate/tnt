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
#include <dat.h>
#include <map.h>
#include <vec.h>
#include "url.h"
#include "conn.h"
#include "http.h"

VEC_GEN(char, char)

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

int http_recieve(conn *conn, http_response *resp)
{
	int lchr, curchr;
	char *hdr_nam; /* Current header name */

	Vec_char tmp;
	http_resp_state state;

	bzero(resp, sizeof(http_response));
	map_header_init(&resp->headers);
	hdr_nam = NULL;

	vec_char_init(&tmp);
	state = VERSION;

	lchr = 0;
	for (; (curchr = conn_getchar(conn)) > 0; lchr = curchr) {
		vec_char_add(&tmp, curchr);

		switch (curchr) {
		case ' ':
			switch (state) {
			case VERSION:
				resp->version = strstrip(tmp.arr, tmp.n - 1);
				tmp.n = 0;
				state = STATUS;
				break;
			case STATUS:
				resp->status = strstrip(tmp.arr, tmp.n - 1);
				tmp.n = 0;
				state = REASON;
				break;
			default:
				break;
			}
			break;

		case ':':
			switch (state) {
			case HDR_NAM:
				hdr_nam = strstrip(tmp.arr, tmp.n - 1);
				tmp.n = 0;
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
				resp->reason = strstrip(tmp.arr, tmp.n - 1);
				tmp.n = 0;
				state = HDR_NAM;
				break;
			case HDR_VAL:
				*map_header_put(&resp->headers, hdr_nam) = strstrip(tmp.arr, tmp.n - 2);
				hdr_nam = NULL;
				tmp.n = 0;
				state = HDR_NAM;
				break;

			/* Message ends by empty header */
			case HDR_NAM:
				if (2 == tmp.n)
					goto success;

			/* CRLF in any other state means a malformed message */
			default:
				goto fail;
			}
			break;
		}


	}

fail:
	if (curchr < 0)
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
	map_header_free(&resp->headers);
	vec_char_free(&tmp);
	return -1;

success:
	vec_char_free(&tmp);
	return 0;
}

int http_send(conn *conn, Vec_str *req)
{
	size_t i, l;
	char arr[4096];

	l = snprintf(arr, sizeof arr, "%s %s %s\r\n",
		req->arr[0], req->arr[1], req->arr[2]);
	if (-1 == conn_write(conn, arr, l))
		goto err_write;

	for (i = 3; i < req->n; i += 2) {
		l = snprintf(arr, sizeof arr, "%s: %s\r\n",
			req->arr[i], req->arr[i + 1]);
		if (-1 == conn_write(conn, arr, l))
			goto err_write;
	}
	if (-1 == conn_write(conn, "\r\n", 2))
		goto err_write;

	return 0;
err_write:
	conn_perror(conn, "conn_write");
	return -1;
}
