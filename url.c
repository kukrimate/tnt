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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "dynarr.h"
#include "url.h"

static char *hexdigits = "0123456789abcdef";

static void addesc(dynarr *x, char c)
{
	dynarr_addc(x, '%');
	dynarr_addc(x, hexdigits[c >> 4 & 0xf]);
	dynarr_addc(x, hexdigits[c & 0xf]);
}

char *urlescape(char *s, size_t n)
{
	char *p;
	dynarr tmp;

	dynarr_new(&tmp, sizeof(char));
	for (p = s; p < s + n; ++p) {
		if (*p <= 0x20) /* control and space */
			addesc(&tmp, *p);
		else
			switch (*p) {
			case '<':
			case '>':
			case '#':
			case '%':
			case '"':
			case '{':
			case '}':
			case '|':
			case '\\':
			case '^':
			case '[':
			case ']':
			case '`':
				addesc(&tmp, *p);
				break;
			default:
				dynarr_addc(&tmp, *p);
				break;
			}
	}
	dynarr_addc(&tmp, 0);
	return tmp.buffer;
}

static int isnum(char *str, size_t len)
{
	char *p;

	for (p = str; p < str + len; ++p) {
		if (*p < 48 || *p > 57)
			return 0;
	}

	return 1;
}

static int sane_getaddrinfo(char *host, uint16_t port, struct addrinfo **out)
{
	char buffer[10];
	int err;

	snprintf(buffer, sizeof(buffer), "%d", port);

	err = getaddrinfo(host, buffer, NULL, out);
	if (err) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		return -1;
	}

	return 0;
}

int url_parse(char *str, url *url)
{
	char *proto_end, *path_start, *port_start;
	long int port;

	url_proto proto;
	char *domain;

	proto_end = strstr(str, "://");
	if (proto_end) {
		if (!strncmp(str, "http", proto_end - str)) {
			proto = PROTO_HTTP;
			port = 80;
		} else if (!strncmp(str, "https", proto_end - str)) {
			proto = PROTO_HTTPS;
			port = 443;
		} else {
			fprintf(stderr, "url_parse: Unknown protocol\n");
			goto err;
		}
		proto_end += 3; /* Skip :// */
	} else {
		proto = PROTO_HTTP;
		port = 80;
		proto_end = str;
	}

	path_start = strchr(proto_end, '/');
	if (!path_start)
		path_start = proto_end + strlen(proto_end);

	port_start = strchr(proto_end, ':');
	if (port_start) {
		if (port_start + 1 >= path_start) {
			fprintf(stderr, "url_parse: Zero length port\n");
			goto err;
		}
		if (!isnum(port_start + 1, path_start - (port_start + 1))) {
			fprintf(stderr, "url_parse: Non-numeric port\n");
			goto err;
		}
		port = strtol(port_start + 1, NULL, 10);
		if (errno || port > 65535) {
			fprintf(stderr, "url_parse: Port out of range\n");
			goto err;
		}
	} else {
		port_start = path_start;
	}

	domain = strndup(proto_end, port_start - proto_end);
	if (-1 == sane_getaddrinfo(domain, (uint16_t) port, &url->server.addr))
		goto err_free;

	url->server.proto    = proto;
	url->server.name     = domain;
	url->server.insecure = 0;
	url->path            = strdup(path_start);
	return 0;
err_free:
	free(domain);
err:
	return -1;
}

void url_free(url *url)
{
	freeaddrinfo(url->server.addr);
	free(url->server.name);
	free(url->path);
}
