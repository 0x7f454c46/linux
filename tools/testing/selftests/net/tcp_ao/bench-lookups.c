// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <arpa/inet.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../../../../include/linux/bits.h"
#include "../../../../include/linux/kernel.h"
#include "aolib.h"

#define AO_KEY_SZ	300 /* ~= sizeof(struct tcp_ao_key) */
#define NR_ITERS	100 /* number of times to run gathering statistics */

#ifdef IPV6_TEST
typedef struct in6_addr ipaddr_t;
static ipaddr_t get_ipaddr_t(ipaddr_t net, size_t n)
{
	ipaddr_t ret = net;

	ret.s6_addr32[3] = htonl(n & (BIT(32) - 1));
	ret.s6_addr32[2] = htonl((n >> 32) & (BIT(32) - 1));

	return ret;
}
#else
typedef struct in_addr ipaddr_t;
static ipaddr_t get_ipaddr_t(ipaddr_t net, size_t n)
{
	ipaddr_t ret;

	ret.s_addr = htonl(ntohl(net.s_addr) + n);
	return ret;
}
#endif

static void gen_test_ips(ipaddr_t *ips, size_t ips_nr, bool use_rand)
{
	ipaddr_t net;
	size_t i, j;

	if (inet_pton(TEST_FAMILY, TEST_NETWORK, &net) != 1)
		test_error("Can't convert ip address %s", TEST_NETWORK);

	if (!use_rand) {
		for (i = 0; i < ips_nr; i++)
			ips[i] = get_ipaddr_t(net, 2 * i + 1);
		return;
	}
	for (i = 0; i < ips_nr; i++) {
		size_t r = (size_t)random() | 0x1;

		ips[i] = get_ipaddr_t(net, r);

		for (j = i - 1; j > 0 && i > 0; j--) {
			if (!memcmp(&ips[i], &ips[j], sizeof(ipaddr_t))) {
				i--; /* collision */
				break;
			}
		}
	}
}

static void test_add_routes(ipaddr_t *ips, size_t ips_nr)
{
	size_t i;

	for (i = 0; i < ips_nr; i++) {
		union tcp_addr *p = (union tcp_addr *)&ips[i];

		if (ip_route_add(veth_name, TEST_FAMILY, this_ip_addr, *p))
			test_error("Failed to add route");
	}
}

static void server_apply_keys(int lsk, ipaddr_t *ips, size_t ips_nr)
{
	size_t i;

	for (i = 0; i < ips_nr; i++) {
		union tcp_addr *p = (union tcp_addr *)&ips[i];

		if (test_add_key(lsk, "password", *p, -1, 100, 100))
			test_error("setsockopt(TCP_AO)");
	}
}

static const size_t nr_keys[] = { 512, 1024, 2048, 4096, 8192, 16384 };
static ipaddr_t *test_ips;

struct bench_stats {
	uint64_t min;
	uint64_t max;
	uint64_t nr;
	double mean;
	double s2;
};

static struct bench_tests {
	struct bench_stats delete_last_key;
	struct bench_stats add_key;
	struct bench_stats delete_rand_key;
	struct bench_stats connect_last_key;
	struct bench_stats connect_rand_key;
	struct bench_stats delete_async;
} bench_results[ARRAY_SIZE(nr_keys)];

#define NSEC_PER_SEC 1000000000ULL

static void measure_call(struct bench_stats *st,
			 void (*f)(int, void *), int sk, void *arg)
{
	struct timespec start = {}, end = {};
	double delta;
	uint64_t nsec;

	if (clock_gettime(CLOCK_MONOTONIC, &start))
		test_error("clock_gettime()");

	f(sk, arg);

	if (clock_gettime(CLOCK_MONOTONIC, &end))
		test_error("clock_gettime()");

	nsec = (end.tv_sec - start.tv_sec) * NSEC_PER_SEC;
	if (end.tv_nsec >= start.tv_nsec)
		nsec += end.tv_nsec - start.tv_nsec;
	else
		nsec -= start.tv_nsec - end.tv_nsec;

	if (st->nr == 0) {
		st->min = st->max = nsec;
	} else {
		if (st->min > nsec)
			st->min = nsec;
		if (st->max < nsec)
			st->max = nsec;
	}

	/* Welford-Knuth algorithm */
	st->nr++;
	delta = (double)nsec - st->mean;
	st->mean += delta / st->nr;
	st->s2 += delta * ((double)nsec - st->mean);
}

static void delete_mkt(int sk, void *arg)
{
	struct tcp_ao_del *ao = arg;

	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_DEL_KEY, ao, sizeof(*ao)))
		test_error("setsockopt(TCP_AO_DEL_KEY)");
}

static void add_back_mkt(int sk, void *arg)
{
	union tcp_addr *p = arg;

	if (test_add_key(sk, "password", *p, -1, 100, 100))
		test_error("setsockopt(TCP_AO)");
}

static void memcpy_sockaddr(void *dest, union tcp_addr *in_addr)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= 0,
		.sin6_addr	= in_addr->a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= 0,
		.sin_addr	= in_addr->a4,
	};
#endif

	memcpy(dest, &addr, sizeof(addr));
}

static void bench_delete(int lsk, struct bench_stats *add,
			 struct bench_stats *del,
			 ipaddr_t *ips, size_t ips_nr,
			 bool rand_order, bool async)
{
	struct tcp_ao_del ao_del = {};
	union tcp_addr *p;
	size_t i;

	ao_del.sndid = 100;
	ao_del.rcvid = 100;
	ao_del.del_async = !!async;
	ao_del.prefix = DEFAULT_TEST_PREFIX;

	/* Remove the first added */
	p = (union tcp_addr *)&ips[0];
	memcpy_sockaddr(&ao_del.addr, p);

	for (i = 0; i < NR_ITERS; i++) {
		measure_call(del, delete_mkt, lsk, (void *)&ao_del);

		/* Restore it back */
		measure_call(add, add_back_mkt, lsk, (void *)p);

		/*
		 * Slowest for FILO-linked-list:
		 * on (i) iteration removing ips[i] element. When it gets
		 * added to the list back - it becomes first to fetch, so
		 * on (i + 1) iteration go to ips[i + 1] element.
		 */
		if (rand_order)
			p = (union tcp_addr *)&ips[rand() % ips_nr];
		else
			p = (union tcp_addr *)&ips[i % ips_nr];
		memcpy_sockaddr(&ao_del.addr, p);
	}
}

static void bench_connect_srv(int lsk, ipaddr_t *ips, size_t ips_nr)
{
	size_t i;

	for (i = 0; i < NR_ITERS; i++) {
		int err, sk;

		synchronize_threads();

		err = test_wait_fd(lsk, TEST_TIMEOUT_SEC, 0);
		if (!err)
			test_error("timeouted for accept()");
		else if (err < 0)
			test_error("test_wait_fd()");

		sk = accept(lsk, NULL, NULL);
		if (sk < 0)
			test_error("accept()");

		close(sk);
	}
}

static void test_print_stats(const char *desc, size_t nr, struct bench_stats *bs)
{
	test_ok("%20s\t%zu keys: min=%" PRIu64 "ms max=%" PRIu64 "ms mean=%gms stddev=%g",
		desc, nr, bs->min / 1000000, bs->max / 1000000,
		bs->mean / 1000000, sqrt((bs->mean / 1000000) / bs->nr));
}

static void *server_fn(void *arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nr_keys); i++) {
		struct bench_tests *bt = &bench_results[i];
		int lsk;

		test_ips = malloc(nr_keys[i] * sizeof(ipaddr_t));
		if (!test_ips)
			test_error("malloc()");

		lsk = test_listen_socket(this_ip_addr, test_server_port + i, 1);

		gen_test_ips(test_ips, nr_keys[i], false);
		test_add_routes(test_ips, nr_keys[i]);
		test_set_optmem(AO_KEY_SZ * nr_keys[i]);
		server_apply_keys(lsk, test_ips, nr_keys[i]);

		synchronize_threads();
		bench_connect_srv(lsk, test_ips, nr_keys[i]);
		bench_connect_srv(lsk, test_ips, nr_keys[i]);

		/* The worst case for FILO-list */
		bench_delete(lsk, &bt->add_key, &bt->delete_last_key,
			     test_ips, nr_keys[i], false, false);
		test_print_stats("Worst case delete",
				nr_keys[i], &bt->delete_last_key);
		test_print_stats("Add a new key",
				nr_keys[i], &bt->add_key);

		bench_delete(lsk, &bt->add_key, &bt->delete_rand_key,
			     test_ips, nr_keys[i], true, false);
		test_print_stats("Remove random-search",
				nr_keys[i], &bt->delete_rand_key);

		bench_delete(lsk, &bt->add_key, &bt->delete_async,
			     test_ips, nr_keys[i], false, true);
		test_print_stats("Remove async", nr_keys[i], &bt->delete_async);

		free(test_ips);
		close(lsk);
	}

	return NULL;
}

static void connect_client(int sk, void *arg)
{
	size_t *p = arg;

	if (test_connect_socket(sk, this_ip_dest, test_server_port + *p) <= 0)
		test_error("failed to connect()");
}

static void client_addr_setup(int sk, union tcp_addr taddr)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= 0,
		.sin6_addr	= taddr.a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= 0,
		.sin_addr	= taddr.a4,
	};
#endif
	int ret;

	ret = ip_addr_add(veth_name, TEST_FAMILY, taddr, TEST_PREFIX);
	if (ret && ret != -EEXIST)
		test_error("Failed to add ip address");
	ret = ip_route_add(veth_name, TEST_FAMILY, taddr, this_ip_dest);
	if (ret && ret != -EEXIST)
		test_error("Failed to add route");

	if (bind(sk, &addr, sizeof(addr)))
		test_error("bind()");
}

static void bench_connect_client(size_t port_off, struct bench_tests *bt,
		ipaddr_t *ips, size_t ips_nr, bool rand_order)
{
	struct bench_stats *con;
	union tcp_addr *p;
	size_t i;

	if (rand_order)
		con = &bt->connect_rand_key;
	else
		con = &bt->connect_last_key;

	p = (union tcp_addr *)&ips[0];

	for (i = 0; i < NR_ITERS; i++) {
		int sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);

		if (sk < 0)
			test_error("socket()");

		client_addr_setup(sk, *p);
		if (test_add_key(sk, "password", this_ip_dest, -1, 100, 100))
			test_error("setsockopt(TCP_AO_ADD_KEY)");

		synchronize_threads();

		measure_call(con, connect_client, sk, (void *)&port_off);

		close(sk);

		/*
		 * Slowest for FILO-linked-list:
		 * on (i) iteration removing ips[i] element. When it gets
		 * added to the list back - it becomes first to fetch, so
		 * on (i + 1) iteration go to ips[i + 1] element.
		 */
		if (rand_order)
			p = (union tcp_addr *)&ips[rand() % ips_nr];
		else
			p = (union tcp_addr *)&ips[i % ips_nr];
	}
}

static void *client_fn(void *arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nr_keys); i++) {
		struct bench_tests *bt = &bench_results[i];

		synchronize_threads();
		bench_connect_client(i, bt, test_ips, nr_keys[i], false);
		test_print_stats("Worst case connect",
				nr_keys[i], &bt->connect_last_key);

		bench_connect_client(i, bt, test_ips, nr_keys[i], false);
		test_print_stats("Connect random-search",
				nr_keys[i], &bt->connect_last_key);
	}
	synchronize_threads();
	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(36, server_fn, client_fn);
	return 0;
}
