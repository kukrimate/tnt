#ifndef URL_H
#define URL_H

/*
 * Escape a string using the method in RFC2396
 */
char *urlescape(char *s, size_t n);

typedef enum {
	PROTO_HTTP,
	PROTO_HTTPS
} url_proto;

typedef struct {
	/*
	 * Protocol
	 */
	url_proto proto;

	/*
	 * Domain name
	 */
	char *domain;

	/*
	 * Port
	 */
	uint16_t port;

	/*
	 * Request path
	 */
	char *path;
} url;

/*
 * Parse a string into a URL structure
 */
int url_parse(char *str, url *url);

/*
 * Free a parsed URL structure
 */
void url_free(url *url);

#endif
