#ifndef HTTP_H
#define HTTP_H

typedef struct {
	/* HTTP version */
	char *version;
	/* Status code */
	char *status;
	/* Reason for status code */
	char *reason;

	/* Hash table with the headers */
	htab headers;
} http_response;

/*
 * Recieve an HTTP response over a connection
 */
int http_recieve(conn *conn, http_response *resp, size_t *consumed);

/*
 * Send an HTTP request over a connection
 */
int http_send(conn *conn, dynarr *req);

#endif
