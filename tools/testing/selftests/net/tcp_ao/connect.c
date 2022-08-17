// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "aolib.h"

static void *server_fn(void *arg)
{
	int err, sk, lsk;
	ssize_t bytes;

	lsk = test_listen_socket(this_ip_addr, test_server_port, 1);

	if (test_set_ao(lsk, "password", 0, this_ip_dest, -1, 100, 100))
		test_error("setsockopt(TCP_AO)");
	synchronize_threads();

	err = test_wait_fd(lsk, TEST_TIMEOUT_SEC, 0);
	if (!err)
		test_error("timeouted for accept()");
	else if (err < 0)
		test_error("test_wait_fd()");

	sk = accept(lsk, NULL, NULL);
	if (sk < 0)
		test_error("accept()");

	synchronize_threads();

	bytes = test_server_run(sk, 0, 0);

	test_fail("server served: %zd", bytes);
	return NULL;
}

static void *client_fn(void *arg)
{
	int sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	uint64_t before_aogood, after_aogood;
	const size_t nr_packets = 20;
	struct netstat *ns_before, *ns_after;

	if (sk < 0)
		test_error("socket()");

	if (test_set_ao(sk, "password", 0, this_ip_dest, -1, 100, 100))
		test_error("setsockopt(TCP_AO)");

	synchronize_threads();
	if (test_connect_socket(sk, this_ip_dest, test_server_port) <= 0)
		test_error("failed to connect()");
	synchronize_threads();

	ns_before = netstat_read();
	before_aogood = netstat_get(ns_before, "TCPAOGood", NULL);
	if (test_client_verify(sk, 100, nr_packets, TEST_TIMEOUT_SEC)) {
		test_fail("verify failed");
		return NULL;
	}

	ns_after = netstat_read();
	after_aogood = netstat_get(ns_after, "TCPAOGood", NULL);
	netstat_print_diff(ns_before, ns_after);
	netstat_free(ns_before);
	netstat_free(ns_after);

	if (nr_packets > (after_aogood - before_aogood)) {
		test_fail("TCPAOGood counter mismatch: %zu > (%zu - %zu)",
				nr_packets, after_aogood, before_aogood);
		return NULL;
	}

	test_ok("connect TCPAOGood %" PRIu64 " => %" PRIu64 ", sent %" PRIu64,
			before_aogood, after_aogood, nr_packets);
	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(1, server_fn, client_fn);
	return 0;
}
