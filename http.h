#ifndef HTTP_H
#define HTTP_H

/*
 * Send an HTTP request and recieve a response
 */
int http_exchange(int sock, dynarr *req, dynarr *resp);

#endif
