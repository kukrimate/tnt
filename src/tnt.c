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
#include <dat.h>
#include <vec.h>
#include <map.h>
#include "url.h"
#include "conn.h"
#include "http.h"

VEC_GEN(char, char)

static int runfuzz(url_server *server, Vec_str *plist)
{
	Vec_str req;
	http_response resp;

	int reconnect;
	conn conn;
	char **cur, **end;
	size_t content_length;

	vec_str_init(&req);
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

		vec_str_add(&req, "GET");
		vec_str_add(&req, *cur);
		vec_str_add(&req, "HTTP/1.1");
		vec_str_add(&req, "Host");
		vec_str_add(&req, server->name);
		vec_str_add(&req, "Connection");
		vec_str_add(&req, "keep-alive");

		if (http_send(&conn, &req) < 0 ||
				http_recieve(&conn, &resp) < 0) {
			conn_close(&conn);
			goto err;
		}
		printf("Path: %s Status: %s\n", *cur++, resp.status);

		// char **valptr = map_header_get(&resp.headers, "Connection");
		// if (valptr && !strcmp(*valptr, "close"))
		reconnect = 1;

		content_length = 0;
		char **valptr = map_header_get(&resp.headers, "Content-Length");
		if (valptr) {
			content_length = strtol(*valptr, NULL, 10);
		}
		if (content_length > 0) {
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
		map_header_free(&resp.headers);
	}

	conn_close(&conn);
	vec_str_free(&req);
	return 0;
err:
	vec_str_free(&req);
	return -1;
}

typedef struct {
	/* Thread ID */
	pthread_t tid;
	/* Target server */
	url_server *server;
	/* List of paths */
	Vec_str plist;
} fuzzthread;

static void *fuzzthread_start(fuzzthread *args)
{
	if (-1 == runfuzz(args->server, &args->plist))
		return NULL;
	return args;
}

static int spawn_threads(int tcount, url_server *server, Vec_str *plist)
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
		vec_str_init(&tptr->plist);
		if (cnt) {
			pleft -= plist->n / tcount;
			vec_str_addall(&tptr->plist, plist->arr + pleft, plist->n / tcount);
		} else {
			vec_str_addall(&tptr->plist, plist->arr, pleft);
		}

		pthread_create(&tptr->tid, NULL,
			(void *(*) (void *)) fuzzthread_start, tptr);
	}

	for (cnt = tcount; cnt--;) {
		pthread_join((--tptr)->tid, &retval);
		if (!retval)
			status = -1;
		vec_str_free(&tptr->plist);
	}

	free(tptr);
	return status;
}

static char *template_gen(char *template, char *old, char *new)
{
	char *begin, *end;
	Vec_char res;

	begin = strstr(template, old);
	if (!begin)
		return NULL;
	end = begin + strlen(old);

	vec_char_init(&res);
	vec_char_addall(&res, template, begin - template);
	vec_char_addall(&res, new, strlen(new));
	vec_char_addall(&res, end, strlen(template) - (end - template));

	begin = urlescape(res.arr, res.n);
	vec_char_free(&res);
	return begin;
}

static int genlist(char *file, char *template, Vec_str *list)
{
	int fd;
	char buf[4096], *bptr, *t;
	ssize_t len;
	size_t i;
	Vec_char tmp;

	fd = open(file, O_RDONLY);
	if (-1 == fd) {
		perror("open");
		return -1;
	}

	vec_char_init(&tmp);

	while (0 < (len = read(fd, buf, sizeof(buf))))
		for (bptr = buf; bptr < buf + len; ++bptr) {
			vec_char_add(&tmp, *bptr);
			if (*bptr == '\n') {
				if (tmp.n > 1) {
					t = strndup(tmp.arr, tmp.n - 1);
					vec_str_add(list, template_gen(template, "FUZZ", t));
					free(t);
				}
				tmp.n = 0;
			}
		}
	/* add last, (unterminated) line if it's not empty */
	if (tmp.n > 1) {
		t = strndup(tmp.arr, tmp.n - 1);
		vec_str_add(list, template_gen(template, "FUZZ", t));
		free(t);
	}

	if (-1 == len) {
		perror("read");
		goto err;
	}

	vec_char_free(&tmp);
	close(fd);
	return 0;

err:
	for (i = 0; i < list->n; ++i)
		free(list->arr[i]);
	vec_char_free(&tmp);
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
	Vec_str wlist;

	if (-1 == url_parse(opt_url, &url))
		return 1;
	url.server.insecure = opt_insecure;

	if (!strstr(url.path, "FUZZ")) {
		fprintf(stderr, "URL must include 'FUZZ'\n");
		goto err_url;
	}

	vec_str_init(&wlist);
	if (-1 == genlist(opt_wordlist, url.path, &wlist)) {
		vec_str_free(&wlist);
		goto err_url;
	}

	if (-1 == spawn_threads(opt_threads, &url.server, &wlist))
	 	goto err_wlist;

	vec_str_free(&wlist);
	url_free(&url);
	return 0;

err_wlist:
	vec_str_free(&wlist);
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
