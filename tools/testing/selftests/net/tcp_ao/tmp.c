// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "aolib.h"
#include <signal.h>

#define NS_WIDTH	10
#define NS_DEPTH	5

static int ___test_listen_socket(int backlog, void *addr, size_t addr_sz)
{
	int sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);

	if (sk < 0)
		test_error("socket()");

	if (bind(sk, (struct sockaddr *)addr, addr_sz) < 0)
		test_error("bind()");

	if (listen(sk, backlog))
		test_error("listen()");

	return sk;
}

static void populate_sk_per_ns(size_t depth, int *port)
{
	size_t i;

	for (i = 0; i < depth; i++) {
		int new_ns = unshare_open_netns();
		sockaddr_af addr;
		int sk;

		tcp_addr_to_sockaddr_in(&addr, &this_ip_addr, htons(*port));
		++*port;

		sk = ___test_listen_socket(1, &addr, sizeof(addr));
		if (sk < 0)
			test_error("socket()");
		if (i % 2) /* will be discovered by lsfd */
			close(new_ns);
	}
}

static void *server_fn(void *arg)
{
	int port = test_server_port;
	size_t i;

	for (i = 0; i <= NS_WIDTH; i++) {
		int old_ns = open_netns();

		populate_sk_per_ns(NS_DEPTH, &port);
		switch_ns(old_ns);
	}

	raise(SIGSTOP);

	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(1, server_fn, NULL);
	return 0;
}
