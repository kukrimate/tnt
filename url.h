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
	 * Address + port
	 */
	struct addrinfo *addr;

	/*
	 * Server name (Used for SNI and Host header)
	 */
	char *name;
} url_server;

typedef struct {
	/*
	 * Server
	 */
	url_server server;

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
