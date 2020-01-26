/*
 * URL parser
 * Author: Mate Kukri
 * License: ISC
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "url.h"

/*
 * Check if a string represents a base 10, positive integer
 */
static int isnum(char *str, size_t len)
{
	char *p;

	for (p = str; p < str + len; ++p) {
		if (*p < 48 || *p > 57)
			return 0;
	}

	return 1;
}

int url_parse(char *str, url *url)
{
	char *p, *p2, *p3;
	long int port;

	/* First look for the protocol field */
	p = strstr(str, "://");
	/* Found protocol field */
	if (p) {
		if (!strncmp(str, "http", p - str)) {
			url->proto = PROTO_HTTP;
			url->port = 80;
		} else if (!strncmp(str, "https", p - str)) {
			url->proto = PROTO_HTTPS;
			url->port = 443;
		} else {
			return -1;
		}
		/* Skip the protocol terminator */
		p += 3;
	/* No protocol field, use default */
	} else {
		url->proto = PROTO_HTTP;
		url->port = 80;
		p = str;
	}

	/* Find the end of the domain */
	p2 = strchr(p, '/');
	if (!p2)
		p2 = p + strlen(p);

	/* Look for port */
	p3 = strchr(p, ':');
	if (p3) {
		/* Port string has to be at least length 1 */
		if (p3+1 >= p2)
			return -1;
		/* Port string has to be a number */
		if (!isnum(p3+1, p2-p3-1))
			return -1;
		/* Do conversion */
		port = strtol(p3+1, NULL, 10);
		/* Make sure conversion didn't overflow */
		if (errno)
			return -1;
		/* Make sure the port is not out of range */
		if (port > 65535)
			return -1;
		url->port = (uint16_t) port;
	} else {
		p3 = p2;
	}

	/* Store domain */
	url->domain = strndup(p, p3 - p);
	/* Store path */
	url->path = strdup(p2);

	return 0;
}

void url_free(url *url)
{
	free(url->domain);
	if (url->path)
		free(url->path);
}
