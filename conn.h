#ifndef CONN_H
#define CONN_H

typedef struct {
    /*
     * Use TLS to connect
     */
	int                 use_tls;
	/*
     * IP (v4) address + port
     */
	struct sockaddr_in  in_addr;
	/*
     * SNI name (TLS SNI)
     */
	char               *sni_name;
} conn_addr;

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
 * Resolv DNS, and create a conn_addr structure
 */
int conn_urltoaddr(url *url, conn_addr *addr);

/*
 * Open a connection to the server
 */
int conn_open(conn_addr *addr, conn *conn);

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
