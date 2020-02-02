#ifndef HTTP_H
#define HTTP_H

/*
 * Recieve an HTTP response over a connection
 */
int http_recieve(conn *conn, dynarr *resp, size_t *content_bytes_consumed);

/*
 * Send an HTTP request over a connection
 */
int http_send(conn *conn, dynarr *req);

#endif
