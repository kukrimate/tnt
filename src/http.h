#ifndef HTTP_H
#define HTTP_H

VEC_GEN(char *, str)
MAP_GEN(char *, char *, strhash, strcmp, header)

typedef struct {
	/* HTTP version */
	char *version;
	/* Status code */
	char *status;
	/* Reason for status code */
	char *reason;

	/* Hash table with the headers */
	Map_header headers;
} http_response;

/*
 * Recieve an HTTP response over a connection
 */
int http_recieve(conn *conn, http_response *resp);

/*
 * Send an HTTP request over a connection
 */
int http_send(conn *conn, Vec_str *req);

#endif
