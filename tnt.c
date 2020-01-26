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

static int readlist(char *path, dynarr *out)
{
	int fd;
	char buf[4096], *bptr;
	ssize_t len;
	size_t i;
	dynarr tmp;

	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		perror("open");
		return -1;
	}

	dynarr_new(&tmp, sizeof(char), 0);

	while (0 < (len = read(fd, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; ++bptr) {
			dynarr_addc(&tmp, *bptr);
			if (*bptr == '\n') {
				if (tmp.elem_count > 1)
					dynarr_addp(out, strndup(tmp.buffer, tmp.elem_count - 1));
				tmp.elem_count = 0;
			}
		}
	/* add last, (unterminated) line if it's not empty */
	if (tmp.elem_count > 1)
		dynarr_addp(out, strndup(tmp.buffer, tmp.elem_count - 1));

	if (-1 == len) {
		perror("read");
		goto err;
	}

	dynarr_del(&tmp);
	close(fd);
	return 0;
err:
	for (i = 0; i < out->elem_count; ++i)
		free(dynarr_getp(out, i));
	dynarr_del(&tmp);
	close(fd);
	return 0;
}

/* Generate new string from template */
static char *template_gen(char *template, char *old, char *new)
{
	char *begin, *end;
	dynarr res;

	begin = strstr(template, old);
	if (!begin)
		return NULL;
	end = begin + strlen(old);

	dynarr_new(&res, sizeof(char), 0);
	dynarr_add(&res, begin - template, template);
	dynarr_add(&res, strlen(new), new);
	dynarr_add(&res, strlen(template) - (end - template), end);
	dynarr_addc(&res, 0);
	return res.buffer;
}

static int runfuzz(struct sockaddr_in *addr, char *template, dynarr *wlist)
{
	dynarr req, resp;
	char *path;
	int sock;
	size_t i_word, i;

	dynarr_new(&req, sizeof(char *), 0);
	dynarr_new(&resp, sizeof(char *), 0);

	for (i_word = 0; i_word < wlist->elem_count; ++i_word) {
		path = template_gen(template, "FUZZ", dynarr_getp(wlist, i_word));
		if (!path) {
			fprintf(stderr, "'FUZZ' missing from your URL\n");
			goto err;
		}

		sock = tcpopen(addr);
		if (-1 == sock) {
			free(path);
			goto err;
		}

		dynarr_addp(&req, "GET");
		dynarr_addp(&req, path);
		dynarr_addp(&req, "HTTP/1.1");
		dynarr_addp(&req, "Host");
		dynarr_addp(&req, "localhost");
		dynarr_addp(&req, "Connection");
		dynarr_addp(&req, "close");

		if (-1 == http_exchange(sock, &req, &resp)) {
			close(sock);
			goto err;
		}
		close(sock);
		printf("Path: %s Status: %s\n", path, (char *) dynarr_getp(&resp, 1));

		/* Free request */
		free(path);
		req.elem_count = 0;

		/* Free response */
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
	/* Template string */
	char *template;
	/* List of keywords */
	dynarr wlist;
} fuzzthread;

static void *fuzzthread_start(fuzzthread *args)
{
	if (-1 == runfuzz(args->addr, args->template, &args->wlist))
		return NULL;
	return args;
}

static int spawn_threads(int tcount, struct sockaddr_in *addr,
	char *template, dynarr *wlist)
{
	fuzzthread thread, *threadptr;
	dynarr thread_list;
	size_t twlist_len, i;
	int status;
	void *retval;

	status = 0;

	/* must_fit set to prevent race-conditions */
	dynarr_new(&thread_list, sizeof(fuzzthread), tcount);
	twlist_len = wlist->elem_count / tcount;

	/* Create threads */
	for (i = 0; i < tcount; ++i) {
		memset(&thread, 0, sizeof(thread));
		thread.addr = addr;
		thread.template = template;

		/* Create thread specific wordlist */
		dynarr_new(&thread.wlist, sizeof(char *), 0);
		if (i == tcount - 1)
			dynarr_add(&thread.wlist, wlist->elem_count - i * twlist_len,
				dynarr_ptr(wlist, i * twlist_len));
		else
			dynarr_add(&thread.wlist, twlist_len,
				dynarr_ptr(wlist, i * twlist_len));

		dynarr_add(&thread_list, 1, &thread);
		threadptr = dynarr_ptr(&thread_list, i);

		pthread_create(&threadptr->tid, NULL,
				(void *(*) (void *)) fuzzthread_start, threadptr);
	}

	/* Wait for all threads */
	for (i = 0; i < thread_list.elem_count; ++i) {
		threadptr = dynarr_ptr(&thread_list, i);
		pthread_join(threadptr->tid, &retval);
		if (!retval)
			status = -1;
		dynarr_del(&threadptr->wlist);
	}

	dynarr_del(&thread_list);
	return status;
}

int main(int argc, char *argv[])
{
	/* Options */
	int opt, opt_threads;
	char *opt_wordlist, *opt_url;

	dynarr wlist;
	url url;
	struct sockaddr_in addr;

	size_t i; /* Loop counter */

	opt_threads = get_nprocs();
	opt_wordlist = NULL;
	opt_url = NULL;

	while (-1 != (opt = getopt(argc, argv, "t:w:u:h")))
		switch (opt) {
		case 't':
			opt_threads = strtol(optarg, NULL, 10);
			if (1 > opt_threads) {
				fprintf(stderr, "Invalid argument for option -- 't'\n");
				goto usage;
			}
			break;
		case 'w':
			opt_wordlist = optarg;
			break;
		case 'u':
			opt_url = optarg;
			break;
		case 'h':
		default:
usage:
			printf("Usage: %s [-t THREADS] -w WORDLIST -u URL\n", argv[0]);
			goto err;
		}
	if (!opt_wordlist) {
		fprintf(stderr, "Required argument missing -- 'w'\n");
		goto usage;
	}
	if (!opt_url) {
		fprintf(stderr, "Required argument missing -- 'u'\n");
		goto usage;
	}

	dynarr_new(&wlist, sizeof(char *), 0);
	if (-1 == readlist(opt_wordlist, &wlist)) {
		dynarr_del(&wlist);
		goto err;
	}
	if (-1 == url_parse(opt_url, &url)) {\
		fprintf(stderr, "Invalid URL\n");
		goto err_del_wlist;
	}
	if (-1 == urltoaddr(&url, &addr))
		goto err_free_url;

	/* Spawn and wait for fuzzing threads */
	if (-1 == spawn_threads(opt_threads, &addr, url.path, &wlist))
		goto err_free_url;

	/* Success cleanup path */
	url_free(&url);
	for (i = 0; i < wlist.elem_count; ++i)
		free(dynarr_getp(&wlist, i));
	dynarr_del(&wlist);
	return 0;

	/* Failure cleanup path */
err_free_url:
	url_free(&url);
err_del_wlist:
	for (i = 0; i < wlist.elem_count; ++i)
		free(dynarr_getp(&wlist, i));
	dynarr_del(&wlist);
err:
	return 1;
}
