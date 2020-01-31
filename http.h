#ifndef HTTP_H
#define HTTP_H

int http_recieve(int sock, dynarr *resp);
int http_send(int sock, dynarr *req);

#endif
