/*
 * Connection wrapper
 * Author: Mate Kukri
 * License: ISC
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <tls.h>
#include "url.h"
#include "conn.h"

int conn_urltoaddr(url *url, conn_addr *addr)
{
	struct hostent *hent;

	hent = gethostbyname(url->domain);
	if (!hent) {
		herror("gethostbyname");
		return -1;
	}

	switch (url->proto) {
	case PROTO_HTTP:
		addr->use_tls = 0;
		break;
	case PROTO_HTTPS:
		addr->use_tls = 1;
		break;
	}

	addr->in_addr.sin_family = AF_INET;
	addr->in_addr.sin_port = htons(url->port);
	addr->in_addr.sin_addr.s_addr = *(in_addr_t *) hent->h_addr;

	addr->sni_name = url->domain;

	return 0;
}

static int tcpopen(struct sockaddr_in *addr)
{
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (-1 == sock) {
		perror("socket");
		return -1;
	}
	if (-1 == connect(sock, addr, sizeof(struct sockaddr_in))) {
		perror("connect");
		return -1;
	}

	return sock;
}

static int tlsopen(conn_addr *addr, conn *conn)
{
	struct tls_config *config;
	struct tls *client;

	config = tls_config_new();
	if (!config)
		abort();
	tls_config_insecure_noverifycert(config);

	client = tls_client();
	if (!client)
		abort();

	if (-1 == tls_configure(client, config) ||
		-1 == tls_connect_socket(client, conn->sockfd, addr->sni_name)) {
		fprintf(stderr, "%s\n", tls_error(client));
		goto err_free;
	}
	if (-1 == tls_handshake(client)) {
		fprintf(stderr, "%s\n", tls_error(client));
		goto err_close;
	}

	conn->tls_client = client;
	tls_config_free(config);
	return 0;

err_close:
	tls_close(client);
err_free:
	tls_free(client);
	tls_config_free(config);
	return -1;
}

int conn_open(conn_addr *addr, conn *conn)
{
	int sockfd;

	sockfd = tcpopen(&addr->in_addr);
	if (-1 == sockfd)
		return -1;

	conn->sockfd     = sockfd;
	conn->tls_client = NULL;
	if (addr->use_tls && -1 == tlsopen(addr, conn)) {
		goto err_close;
	}

	return 0;
err_close:
	close(sockfd);
	conn->sockfd = 0;
	return -1;
}

ssize_t conn_write(conn *conn, void *buf, size_t nbyte)
{
	if (conn->tls_client)
		return tls_write(conn->tls_client, buf, nbyte);
	else
		return write(conn->sockfd, buf, nbyte);
}

ssize_t conn_read(conn *conn, void *buf, size_t nbyte)
{
	if (conn->tls_client)
		return tls_read(conn->tls_client, buf, nbyte);
	else
		return read(conn->sockfd, buf, nbyte);
}

void conn_close(conn *conn)
{
	if (conn->tls_client) {
		tls_close(conn->tls_client);
		tls_free(conn->tls_client);
	}
	close(conn->sockfd);
}
