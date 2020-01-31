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
	char *proto_end, *path_start, *port_start;
	long int port;

	proto_end = strstr(str, "://");
	if (proto_end) {
		if (!strncmp(str, "http", proto_end - str)) {
			url->proto = PROTO_HTTP;
			url->port = 80;
		} else if (!strncmp(str, "https", proto_end - str)) {
			url->proto = PROTO_HTTPS;
			url->port = 443;
		} else {
			return -1;
		}
		proto_end += 3; /* Skip :// */
	} else {
		url->proto = PROTO_HTTP;
		url->port = 80;
		proto_end = str;
	}

	path_start = strchr(proto_end, '/');
	if (!path_start)
		path_start = proto_end + strlen(proto_end);

	port_start = strchr(proto_end, ':');
	if (port_start) {
		if (port_start + 1 >= path_start)
			return -1;
		if (!isnum(port_start + 1, path_start - (port_start + 1)))
			return -1;
		port = strtol(port_start + 1, NULL, 10);
		if (errno) /* Make sure conversion didn't overflow */
			return -1;
		if (port > 65535) /* Make sure the port is not out of range */
			return -1;
		url->port = (uint16_t) port;
	} else {
		port_start = path_start;
	}

	url->domain = strndup(proto_end, port_start - proto_end);
	url->path = strdup(path_start);
	return 0;
}

void url_free(url *url)
{
	free(url->domain);
	free(url->path);
}
