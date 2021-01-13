/*
 * TNT web fuzzer
 * Author: Mate Kukri
 * License: ISC
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <vec.h>
#include <djb2.h>
#include <map.h>
#include "url.h"
#include "conn.h"
#include "http.h"

VEC_GEN(char, c)

static int runfuzz(url_server *server, str_vec *plist)
{
	str_vec req;
	http_response resp;

	int reconnect;
	conn conn;
	char **cur, **end, *tmp;
	size_t content_length;

	str_vec_init(&req);
	reconnect = 0;
	if (-1 == conn_open(server, &conn))
		goto err;

	cur = plist->arr;
	end = plist->arr + plist->n;

	while (cur < end) {
		if (reconnect) {
			conn_close(&conn);
			if (-1 == conn_open(server, &conn))
				goto err;
			reconnect = 0;
		}

		str_vec_add(&req, "GET");
		str_vec_add(&req, *cur);
		str_vec_add(&req, "HTTP/1.1");
		str_vec_add(&req, "Host");
		str_vec_add(&req, server->name);
		str_vec_add(&req, "Connection");
		str_vec_add(&req, "keep-alive");

		if (http_send(&conn, &req) < 0 ||
				http_recieve(&conn, &resp) < 0) {
			conn_close(&conn);
			goto err;
		}
		printf("Path: %s Status: %s\n", *cur++, resp.status);

		if (header_map_get(&resp.headers, "Connection", &tmp)
				&& !strcmp(tmp, "close"))
			reconnect = 1;
		if (header_map_get(&resp.headers, "Content-Length", &tmp)
				&& (content_length = strtol(tmp, NULL, 10)) > 0) {
			/* Try to dispose of content if it exists */
			if (conn_dispose(&conn, content_length) < 0) {
				conn_close(&conn);
				goto err;
			}
		}

		/* Discard request */
		req.n = 0;

		/* Discard response */
		free(resp.version);
		free(resp.status);
		free(resp.reason);
		header_map_free(&resp.headers);
	}

	conn_close(&conn);
	str_vec_free(&req);
	return 0;
err:
	str_vec_free(&req);
	return -1;
}

typedef struct {
	/* Thread ID */
	pthread_t tid;
	/* Target server */
	url_server *server;
	/* List of paths */
	str_vec plist;
} fuzzthread;

static void *fuzzthread_start(fuzzthread *args)
{
	if (-1 == runfuzz(args->server, &args->plist))
		return NULL;
	return args;
}

static int spawn_threads(int tcount, url_server *server, str_vec *plist)
{
	int status;
	fuzzthread *tptr;
	size_t pleft, cnt;
	void *retval;

	status = 0;
	tptr = malloc(tcount * sizeof(fuzzthread));
	if (!tptr)
		abort();
	pleft = plist->n;

	for (cnt = tcount; cnt--; ++tptr) {
		tptr->server = server;
		str_vec_init(&tptr->plist);
		if (cnt) {
			pleft -= plist->n / tcount;
			str_vec_addall(&tptr->plist, plist->arr + pleft, plist->n / tcount);
		} else {
			str_vec_addall(&tptr->plist, plist->arr, pleft);
		}

		pthread_create(&tptr->tid, NULL,
			(void *(*) (void *)) fuzzthread_start, tptr);
	}

	for (cnt = tcount; cnt--;) {
		pthread_join((--tptr)->tid, &retval);
		if (!retval)
			status = -1;
		str_vec_free(&tptr->plist);
	}

	free(tptr);
	return status;
}

static char *template_gen(char *template, char *old, char *new)
{
	char *begin, *end;
	cvec res;

	begin = strstr(template, old);
	if (!begin)
		return NULL;
	end = begin + strlen(old);

	cvec_init(&res);
	cvec_addall(&res, template, begin - template);
	cvec_addall(&res, new, strlen(new));
	cvec_addall(&res, end, strlen(template) - (end - template));

	begin = urlescape(res.arr, res.n);
	cvec_free(&res);
	return begin;
}

static int genlist(char *file, char *template, str_vec *list)
{
	int fd;
	char buf[4096], *bptr, *t;
	ssize_t len;
	size_t i;
	cvec tmp;

	fd = open(file, O_RDONLY);
	if (-1 == fd) {
		perror("open");
		return -1;
	}

	cvec_init(&tmp);

	while (0 < (len = read(fd, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; ++bptr) {
			cvec_add(&tmp, *bptr);
			if (*bptr == '\n') {
				if (tmp.n > 1) {
					t = strndup(tmp.arr, tmp.n - 1);
					str_vec_add(list, template_gen(template, "FUZZ", t));
					free(t);
				}
				tmp.n = 0;
			}
		}
	/* add last, (unterminated) line if it's not empty */
	if (tmp.n > 1) {
		t = strndup(tmp.arr, tmp.n - 1);
		str_vec_add(list, template_gen(template, "FUZZ", t));
		free(t);
	}

	if (-1 == len) {
		perror("read");
		goto err;
	}

	cvec_free(&tmp);
	close(fd);
	return 0;

err:
	for (i = 0; i < list->n; ++i)
		free(list->arr[i]);
	cvec_free(&tmp);
	close(fd);
	return -1;
}


/*
 * Actual program functionality called from 'main' after option parsing
 */
static int prog(int opt_threads, int opt_insecure,
	char *opt_wordlist, char *opt_url)
{
	url url;
	str_vec wlist;

	if (-1 == url_parse(opt_url, &url))
		return 1;
	url.server.insecure = opt_insecure;

	if (!strstr(url.path, "FUZZ")) {
		fprintf(stderr, "URL must include 'FUZZ'\n");
		goto err_url;
	}

	str_vec_init(&wlist);
	if (-1 == genlist(opt_wordlist, url.path, &wlist)) {
		str_vec_free(&wlist);
		goto err_url;
	}

	if (-1 == spawn_threads(opt_threads, &url.server, &wlist))
	 	goto err_wlist;

	str_vec_free(&wlist);
	url_free(&url);
	return 0;

err_wlist:
	str_vec_free(&wlist);
err_url:
	url_free(&url);
	return 1;
}

int main(int argc, char *argv[])
{
	int opt, opt_threads, opt_insecure;
	char *opt_wordlist, *opt_url;

	opt_threads = get_nprocs();
	opt_insecure = 0;
	opt_wordlist = NULL;
	opt_url = NULL;

	while (-1 != (opt = getopt(argc, argv, "t:iw:u:h")))
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
		case 'i':
			opt_insecure = 1;
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

	return prog(opt_threads, opt_insecure, opt_wordlist, opt_url);
usage:
	printf("Usage: %s [-t THREADS] [-i] -w WORDLIST -u URL\n", argv[0]);
	return 1;
}
