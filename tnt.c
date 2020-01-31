/*
 * TNT web fuzzer
 * Author: Mate Kukri
 * License: ISC
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include "dynarr.h"
#include "url.h"
#include "http.h"

static int urltoaddr(url *url, struct sockaddr_in *addr)
{
	struct hostent *hent;

	hent = gethostbyname(url->domain);
	if (!hent) {
		herror("gethostbyname");
		return -1;
	}

	addr->sin_family = AF_INET;
	addr->sin_port = htons(url->port);
	addr->sin_addr.s_addr = *(in_addr_t *) hent->h_addr;

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

static int runfuzz(struct sockaddr_in *addr, char *host, dynarr *plist)
{
	dynarr req, resp;
	int reconnect, sock;
	char **cur, *end;
	size_t i;

	dynarr_new(&req, sizeof(char *));
	dynarr_new(&resp, sizeof(char *));

	reconnect = 0;
	sock = tcpopen(addr);
	if (-1 == sock)
		goto err;

	cur = dynarr_ptr(plist, 0);
	end = (char *) plist->buffer + plist->elem_size * plist->elem_count;

	while ((char *) cur < end) {
		if (reconnect) {
			close(sock);
			sock = tcpopen(addr);
			if (-1 == sock)
				goto err;
			reconnect = 0;
		}

		dynarr_addp(&req, "GET");
		dynarr_addp(&req, *cur);
		dynarr_addp(&req, "HTTP/1.1");
		dynarr_addp(&req, "Host");
		dynarr_addp(&req, host);
		dynarr_addp(&req, "Connection");
		dynarr_addp(&req, "keep-alive");

		if (-1 == http_send(sock, &req) ||
				-1 == http_recieve(sock, &resp)) {
			close(sock);
			goto err;
		}
		printf("Path: %s Status: %s\n", *cur++, (char *) dynarr_getp(&resp, 1));

		for (i = 3; i < resp.elem_count; i+=2) {
			if (!strcasecmp(dynarr_getp(&resp, i), "Connection") &&
					!strcasecmp(dynarr_getp(&resp, i + 1), "close"))
				reconnect = 1;
		}

		/* Discard request */
		req.elem_count = 0;

		/* Discard response */
		for (i = 0; i < resp.elem_count; ++i)
			free(dynarr_getp(&resp, i));
		resp.elem_count = 0;
	}

	dynarr_del(&req);
	dynarr_del(&resp);
	return 0;
err:
	dynarr_del(&req);
	dynarr_del(&resp);
	return -1;
}

typedef struct {
	/* Thread ID */
	pthread_t tid;
	/* Address of the target server */
	struct sockaddr_in *addr;
	/* Host string */
	char *host;
	/* List of paths */
	dynarr plist;
} fuzzthread;

static void *fuzzthread_start(fuzzthread *args)
{
	if (-1 == runfuzz(args->addr, args->host, &args->plist))
		return NULL;
	return args;
}

static int spawn_threads(int tcount, struct sockaddr_in *addr, char *host,
	dynarr *plist)
{
	int status;
	fuzzthread *tptr;
	size_t pleft, cnt;
	void *retval;

	status = 0;
	tptr = malloc(tcount * sizeof(fuzzthread));
	pleft = plist->elem_count;

	for (cnt = tcount; cnt--; ++tptr) {
		tptr->addr = addr;
		tptr->host = host;

		dynarr_new(&tptr->plist, sizeof(char *));
		if (cnt) {
			pleft -= plist->elem_count / tcount;
			dynarr_add(&tptr->plist, plist->elem_count / tcount,
				dynarr_ptr(plist, pleft));
		} else {
			dynarr_add(&tptr->plist, pleft,	plist->buffer);
		}

		pthread_create(&tptr->tid, NULL,
			(void *(*) (void *)) fuzzthread_start, tptr);
	}

	for (cnt = tcount; cnt--;) {
		pthread_join((--tptr)->tid, &retval);
		if (!retval)
			status = -1;
		dynarr_del(&tptr->plist);
	}

	free(tptr);
	return status;
}

static char *template_gen(char *template, char *old, char *new)
{
	char *begin, *end;
	dynarr res;

	begin = strstr(template, old);
	if (!begin)
		return NULL;
	end = begin + strlen(old);

	dynarr_new(&res, sizeof(char));
	dynarr_add(&res, begin - template, template);
	dynarr_add(&res, strlen(new), new);
	dynarr_add(&res, strlen(template) - (end - template), end);
	dynarr_addc(&res, 0);
	return res.buffer;
}

static int genlist(char *file, char *template, dynarr *list)
{
	int fd;
	char buf[4096], *bptr, *t;
	ssize_t len;
	size_t i;
	dynarr tmp;

	fd = open(file, O_RDONLY);
	if (-1 == fd) {
		perror("open");
		return -1;
	}

	dynarr_new(&tmp, sizeof(char));

	while (0 < (len = read(fd, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; ++bptr) {
			dynarr_addc(&tmp, *bptr);
			if (*bptr == '\n') {
				if (tmp.elem_count > 1) {
					t = strndup(tmp.buffer, tmp.elem_count - 1);
					dynarr_addp(list, template_gen(template, "FUZZ", t));
					free(t);
				}
				tmp.elem_count = 0;
			}
		}
	/* add last, (unterminated) line if it's not empty */
	if (tmp.elem_count > 1) {
		t = strndup(tmp.buffer, tmp.elem_count - 1);
		dynarr_addp(list, template_gen(template, "FUZZ", t));
		free(t);
	}

	if (-1 == len) {
		perror("read");
		goto err;
	}

	dynarr_del(&tmp);
	close(fd);
	return 0;

err:
	for (i = 0; i < list->elem_count; ++i)
		free(dynarr_getp(list, i));
	dynarr_del(&tmp);
	close(fd);
	return -1;
}


/*
 * Actual program functionality called from 'main' after option parsing
 */
static int prog(int opt_threads, char *opt_wordlist, char *opt_url)
{
	url url;
	dynarr wlist;
	struct sockaddr_in addr;

	if (-1 == url_parse(opt_url, &url)) {
		fprintf(stderr, "Invalid URL\n");
		return 1;
	}
	if (!strstr(url.path, "FUZZ")) {
		fprintf(stderr, "URL must include 'FUZZ'\n");
		goto err_url;
	}

	dynarr_new(&wlist, sizeof(char *));
	if (-1 == genlist(opt_wordlist, url.path, &wlist)) {
		dynarr_del(&wlist);
		goto err_url;
	}

	if (-1 == urltoaddr(&url, &addr) ||
		-1 == spawn_threads(opt_threads, &addr, url.domain, &wlist))
		goto err_wlist;

	dynarr_delall(&wlist);
	url_free(&url);
	return 0;

err_wlist:
	dynarr_delall(&wlist);
err_url:
	url_free(&url);
	return 1;
}

int main(int argc, char *argv[])
{
	int opt, opt_threads;
	char *opt_wordlist, *opt_url;

	opt_threads = get_nprocs();
	opt_wordlist = NULL;
	opt_url = NULL;

	while (-1 != (opt = getopt(argc, argv, "t:w:u:h")))
		switch (opt) {
		case 't':
			opt_threads = strtol(optarg, NULL, 10);
			break;
		case 'w':
			opt_wordlist = optarg;
			break;
		case 'u':
			opt_url = optarg;
			break;
		case 'h':
		default:
			goto usage;
		}

	if (1 > opt_threads) {
		fprintf(stderr, "Invalid argument for option -- 't'\n");
		goto usage;
	}
	if (!opt_wordlist) {
		fprintf(stderr, "Required argument missing -- 'w'\n");
		goto usage;
	}
	if (!opt_url) {
		fprintf(stderr, "Required argument missing -- 'u'\n");
		goto usage;
	}

	return prog(opt_threads, opt_wordlist, opt_url);
usage:
	printf("Usage: %s [-t THREADS] -w WORDLIST -u URL\n", argv[0]);
	return 1;
}
