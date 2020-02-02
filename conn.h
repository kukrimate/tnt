#ifndef CONN_H
#define CONN_H

typedef struct {
	/*
	 * File Descriptor for the socket
	 */
	int sockfd;
	/*
	 * TLS client (NULL on plain-text connections)
	 */
	void *tls_client;
} conn;

/*
 * Open a connection to the server
 */
int conn_open(url_server *server, conn *conn);

/*
 * Print read/write errors
 */
void conn_perror(conn *conn, char *s);

/*
 * Write to a connection
 */
ssize_t conn_write(conn *conn, void *buf, size_t nbyte);

/*
 * Read from a conncetion
 */
ssize_t conn_read(conn *conn, void *buf, size_t nbyte);

/*
 * Close a connection
 */
void conn_close(conn *conn);

#endif
