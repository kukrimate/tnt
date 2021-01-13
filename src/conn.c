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

static int tcpopen(struct sockaddr *addr, socklen_t addr_len)
{
	int sock;

	sock = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (-1 == sock) {
		perror("socket");
		return -1;
	}
	if (-1 == connect(sock, addr, addr_len)) {
		perror("connect");
		return -1;
	}

	return sock;
}

static int tlsopen(int sockfd, char *sni_name, int insecure,
	struct tls **out_client)
{
	struct tls_config *config;
	struct tls *client;

	config = tls_config_new();
	if (!config)
		abort();
	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
		tls_config_insecure_noverifytime(config);
	}

	client = tls_client();
	if (!client)
		abort();

	if (-1 == tls_configure(client, config) ||
		-1 == tls_connect_socket(client, sockfd, sni_name)) {
		fprintf(stderr, "%s\n", tls_error(client));
		goto err_free;
	}
	if (-1 == tls_handshake(client)) {
		fprintf(stderr, "%s\n", tls_error(client));
		goto err_close;
	}

	*out_client = client;
	tls_config_free(config);
	return 0;

err_close:
	tls_close(client);
err_free:
	tls_free(client);
	tls_config_free(config);
	return -1;
}

int conn_open(url_server *server, conn *conn)
{
	int sockfd;

	sockfd = tcpopen(server->addr->ai_addr, server->addr->ai_addrlen);
	if (-1 == sockfd)
		return -1;

	if (server->proto == PROTO_HTTPS) {
		if (-1 == tlsopen(sockfd, server->name,
				server->insecure, (struct tls **) &conn->tls_client))
			goto err_close;
	} else {
		conn->tls_client = NULL;
	}

	conn->sockfd = sockfd;
	return 0;

err_close:
	close(sockfd);
	return -1;
}

void conn_perror(conn *conn, char *s)
{
	if (conn->tls_client)
		fprintf(stderr, "%s: %s\n", s, tls_error(conn->tls_client));
	else
		perror(s);
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
	else {
		return read(conn->sockfd, buf, nbyte);
	}
}

int conn_getchar(conn *conn)
{
	int err;
	char ch;

	err = conn_read(conn, &ch, 1);
	if (err > 0)
		return (int) ch;
	else
		return err;
}

int conn_dispose(conn *conn, size_t n)
{
	char buf[4096];

	for (; n > sizeof buf; n -= sizeof buf)
		if (conn_read(conn, buf, sizeof buf) < 0)
			return -1;

	if (n && conn_read(conn, buf, n) < 0)
		return -1;

	return 0;
}

void conn_close(conn *conn)
{
	if (conn->tls_client) {
		tls_close(conn->tls_client);
		tls_free(conn->tls_client);
	}
	close(conn->sockfd);
}
