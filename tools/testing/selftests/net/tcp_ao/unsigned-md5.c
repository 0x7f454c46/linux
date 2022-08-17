// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "aolib.h"
#include "../../../../include/linux/bits.h"

typedef uint8_t fault_t;
#define F_TIMEOUT	1
#define F_KEYREJECT	2
#define F_PREINSTALL	3
#define F_POSTINSTALL	4

#define fault(type)	(inj == type)

static const char *md5_password = "Some evil genius, enemy to mankind, must have been the first contriver.";
static const char *ao_password = "In this hour, I do not believe that any darkness will endure.";

static union tcp_addr client2;
static union tcp_addr client3;

static int test_set_md5(int sk, const union tcp_addr in_addr, uint8_t prefix)
{
	size_t pwd_len = strlen(md5_password);
	struct tcp_md5sig md5sig = {};
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= 0,
		.sin6_addr	= in_addr.a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= 0,
		.sin_addr	= in_addr.a4,
	};
#endif

	if (prefix > DEFAULT_TEST_PREFIX)
		prefix = DEFAULT_TEST_PREFIX;

	md5sig.tcpm_keylen = pwd_len;
	memcpy(md5sig.tcpm_key, md5_password, pwd_len);
	md5sig.tcpm_flags = TCP_MD5SIG_FLAG_PREFIX;
	md5sig.tcpm_prefixlen = prefix;
	memcpy(&md5sig.tcpm_addr, &addr, sizeof(addr));

	return setsockopt(sk, IPPROTO_TCP, TCP_MD5SIG_EXT,
			  &md5sig, sizeof(md5sig));
}

static bool tcp_md5_enabled = true;
static void check_tcp_md5_support(void)
{
	int sk;
	union tcp_addr addr_any = {};

	sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		test_error("socket()");

	if (test_set_md5(sk, addr_any, 0)) {
		if (errno == ENOPROTOOPT)
			tcp_md5_enabled = false;
		else
			test_error("setsockopt(TCP_MD5SIG_EXT)");
	}
	close(sk);
}

static void try_accept(const char *tst_name, unsigned int port,
		       union tcp_addr *md5_addr, uint8_t md5_prefix,
		       union tcp_addr *ao_addr, uint8_t ao_prefix,
		       uint8_t sndid, uint8_t rcvid, const char *cnt_name,
		       bool needs_md5, fault_t inj)
{
	uint64_t before_cnt, after_cnt;
	int lsk, err, sk = 0;
	time_t timeout;

	if (needs_md5 && !tcp_md5_enabled) {
		test_skip("%s: setsockopt(TCP_MD5SIG_EXT) is not supported", tst_name);
		return;
	}

	lsk = test_listen_socket(this_ip_addr, port, 1);

	if (md5_addr && test_set_md5(lsk, *md5_addr, md5_prefix))
		test_error("setsockopt(TCP_MD5SIG_EXT)");

	if (ao_addr && test_set_ao(lsk, ao_password, 0, *ao_addr,
				   ao_prefix, sndid, rcvid))
		test_error("setsockopt(TCP_AO)");

	if (cnt_name)
		before_cnt = netstat_get_one(cnt_name, NULL);

	synchronize_threads(); /* preparations done */

	timeout = fault(F_TIMEOUT) ? TEST_RETRANSMIT_SEC : TEST_TIMEOUT_SEC;
	err = test_wait_fd(lsk, timeout, 0);
	if (err < 0)
		test_error("test_wait_fd()");
	else if (!err) {
		if (!fault(F_TIMEOUT))
			test_fail("timeouted for accept()");
	} else {
		if (fault(F_TIMEOUT))
			test_fail("ready to accept");

		sk = accept(lsk, NULL, NULL);
		if (sk < 0) {
			test_error("accept()");
		} else {
			if (fault(F_TIMEOUT))
				test_fail("%s: accepted", tst_name);
		}
	}

	close(lsk);

	if (!cnt_name)
		goto out;

	after_cnt = netstat_get_one(cnt_name, NULL);

	if (after_cnt <= before_cnt) {
		test_fail("%s: %s counter did not increase: %zu <= %zu",
				tst_name, cnt_name, after_cnt, before_cnt);
	} else {
		test_ok("%s: counter %s increased %zu => %zu",
			tst_name, cnt_name, before_cnt, after_cnt);
	}

out:
	synchronize_threads(); /* close() */
	if (sk > 0)
		close(sk);
}

static void server_add_routes(void)
{
	int family = TEST_FAMILY;

	check_tcp_md5_support();
	synchronize_threads(); /* client_add_ips() */

	if (ip_route_add(veth_name, family, this_ip_addr, client2))
		test_error("Failed to add route");
	if (ip_route_add(veth_name, family, this_ip_addr, client3))
		test_error("Failed to add route");
}

static void server_add_fail_tests(unsigned int *port)
{
	union tcp_addr addr_any = {};

	try_accept("TCP-AO established: add TCP-MD5 key", (*port)++, NULL, 0,
		   &addr_any, 0, 100, 100, "TCPAOGood", true, 0);
	try_accept("TCP-MD5 established: add TCP-AO key", (*port)++, &addr_any, 0,
		   NULL, 0, 0, 0, NULL, true, 0);
	try_accept("non-signed established: add TCP-AO key", (*port)++, NULL, 0,
		   NULL, 0, 0, 0, "CurrEstab", false, 0);
}

static void *server_fn(void *arg)
{
	unsigned int port = test_server_port;
	union tcp_addr addr_any = {};

	server_add_routes();

	try_accept("AO server (INADDR_ANY): AO client", port++, NULL, 0,
		   &addr_any, 0, 100, 100, "TCPAOGood", false, 0);
	try_accept("AO server (INADDR_ANY): MD5 client", port++, NULL, 0,
		   &addr_any, 0, 100, 100, "TCPMD5Unexpected", true, F_TIMEOUT);
	try_accept("AO server (INADDR_ANY): no sign client", port++, NULL, 0,
		   &addr_any, 0, 100, 100, "TCPAORequired", false, F_TIMEOUT);

	try_accept("MD5 server (INADDR_ANY): AO client", port++, &addr_any, 0,
		   NULL, 0, 0, 0, "TCPAOKeyNotFound", true, F_TIMEOUT);
	try_accept("MD5 server (INADDR_ANY): MD5 client", port++, &addr_any, 0,
		   NULL, 0, 0, 0, NULL, true, 0);
	try_accept("MD5 server (INADDR_ANY): no sign client", port++, &addr_any, 0,
		   NULL, 0, 0, 0, "TCPMD5NotFound", true, F_TIMEOUT);

	try_accept("no sign server: AO client", port++, NULL, 0,
		   NULL, 0, 0, 0, "TCPAOKeyNotFound", false, F_TIMEOUT);
	try_accept("no sign server: MD5 client", port++, NULL, 0,
		   NULL, 0, 0, 0, "TCPMD5Unexpected", true, F_TIMEOUT);
	try_accept("no sign server: no sign client", port++, NULL, 0,
		   NULL, 0, 0, 0, "CurrEstab", false, 0);

	try_accept("AO+MD5 server: AO client (matching)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPAOGood", true, 0);
	try_accept("AO+MD5 server: AO client (misconfig, matching MD5)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPAOKeyNotFound", true, F_TIMEOUT);
	try_accept("AO+MD5 server: AO client (misconfig, non-matching)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPAOKeyNotFound", true, F_TIMEOUT);
	try_accept("AO+MD5 server: MD5 client (matching)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, NULL, true, 0);
	try_accept("AO+MD5 server: MD5 client (misconfig, matching AO)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPMD5Unexpected", true, F_TIMEOUT);
	try_accept("AO+MD5 server: MD5 client (misconfig, non-matching)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPMD5Unexpected", true, F_TIMEOUT);
	try_accept("AO+MD5 server: no sign client (unmatched)", port++,
		&this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "CurrEstab", true, 0);
	try_accept("AO+MD5 server: no sign client (misconfig, matching AO)",
		port++, &this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPAORequired", true, F_TIMEOUT);
	try_accept("AO+MD5 server: no sign client (misconfig, matching MD5)",
		port++, &this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, "TCPMD5NotFound", true, F_TIMEOUT);

	try_accept("AO+MD5 server: client with both [TCP-MD5] and TCP-AO keys",
		port++, &this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, NULL, true, F_TIMEOUT);
	try_accept("AO+MD5 server: client with both TCP-MD5 and [TCP-AO] keys",
		port++, &this_ip_dest, TEST_PREFIX, &client2, TEST_PREFIX,
		100, 100, NULL, true, F_TIMEOUT);

	server_add_fail_tests(&port);

	/* client exits */
	synchronize_threads();
	return NULL;
}

static int client_bind(int sk, union tcp_addr bind_addr)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= 0,
		.sin6_addr	= bind_addr.a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= 0,
		.sin_addr	= bind_addr.a4,
	};
#endif
	return bind(sk, &addr, sizeof(addr));
}

static void try_connect(const char *tst_name, unsigned int port,
		       union tcp_addr *md5_addr, uint8_t md5_prefix,
		       union tcp_addr *ao_addr, uint8_t ao_prefix,
		       uint8_t sndid, uint8_t rcvid, fault_t inj,
		       bool needs_md5, union tcp_addr *bind_addr)
{
	time_t timeout;
	int sk, ret;

	if (needs_md5 && !tcp_md5_enabled) {
		test_skip("%s: setsockopt(TCP_MD5SIG_EXT) is not supported", tst_name);
		return;
	}

	sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		test_error("socket()");

	if (bind_addr && client_bind(sk, *bind_addr))
		test_error("bind()");

	if (md5_addr && test_set_md5(sk, *md5_addr, md5_prefix))
		test_error("setsockopt(TCP_MD5SIG_EXT)");

	if (ao_addr && test_set_ao(sk, ao_password, 0, *ao_addr,
				   ao_prefix, sndid, rcvid))
		test_error("setsockopt(TCP_AO)");

	synchronize_threads(); /* preparations done */

	timeout = fault(F_TIMEOUT) ? TEST_RETRANSMIT_SEC : TEST_TIMEOUT_SEC;
	ret = _test_connect_socket(sk, this_ip_dest, port, timeout);

	if (ret < 0) {
		if (fault(F_KEYREJECT) && ret == -EKEYREJECTED) {
			test_ok("%s: connect() was prevented", tst_name);
			goto out;
		} else if (ret == -ECONNREFUSED &&
				(fault(F_TIMEOUT) || fault(F_KEYREJECT))) {
			test_ok("%s: refused to connect", tst_name);
			goto out;
		} else {
			test_error("%s: connect() returned %d", tst_name, ret);
		}
	}

	if (ret == 0) {
		if (fault(F_TIMEOUT))
			test_ok("%s", tst_name);
		else
			test_fail("%s: failed to connect()", tst_name);
	} else {
		if (fault(F_TIMEOUT) || fault(F_KEYREJECT))
			test_fail("%s: connected", tst_name);
		else
			test_ok("%s: connected", tst_name);
	}

out:
	synchronize_threads(); /* close() */
	/* _test_connect_socket() cleans up on failure */
	if (ret > 0)
		close(sk);
}

#define PREINSTALL_MD5	BIT(1)
#define POSTINSTALL_MD5	BIT(2)
#define PREINSTALL_AO	BIT(3)
#define POSTINSTALL_AO	BIT(4)

static void try_to_add(const char *tst_name, unsigned int port,
		       unsigned int strategy,
		       union tcp_addr md5_addr, uint8_t md5_prefix,
		       union tcp_addr ao_addr, uint8_t ao_prefix,
		       uint8_t sndid, uint8_t rcvid,
		       bool needs_md5, fault_t inj)
{
	time_t timeout;
	int sk, ret;

	if (needs_md5 && !tcp_md5_enabled) {
		test_skip("%s: setsockopt(TCP_MD5SIG_EXT) is not supported", tst_name);
		return;
	}

	sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		test_error("socket()");

	if (client_bind(sk, this_ip_addr))
		test_error("bind()");

	if (strategy & PREINSTALL_MD5) {
		if (test_set_md5(sk, md5_addr, md5_prefix))
			test_error("setsockopt(TCP_MD5SIG_EXT)");
	}

	if (strategy & PREINSTALL_AO) {
		if (test_set_ao(sk, ao_password, 0, ao_addr,
				ao_prefix, sndid, rcvid)) {
			if (fault(F_PREINSTALL)) {
				test_ok("%s: prefailed as expected", tst_name);
				goto out_no_sync;
			} else {
				test_error("setsockopt(TCP_AO)");
			}
		} else if (fault(F_PREINSTALL)) {
			test_fail("%s: setsockopt()s were expected to fail", tst_name);
			goto out_no_sync;
		}
	}

	synchronize_threads(); /* preparations done */

	timeout = fault(F_TIMEOUT) ? TEST_RETRANSMIT_SEC : TEST_TIMEOUT_SEC;
	ret = _test_connect_socket(sk, this_ip_dest, port, timeout);

	if (ret <= 0) {
		test_error("%s: connect() returned %d", tst_name, ret);
		goto out;
	}

	if (strategy & POSTINSTALL_MD5) {
		if (test_set_md5(sk, md5_addr, md5_prefix)) {
			if (fault(F_POSTINSTALL)) {
				test_ok("%s: postfailed as expected", tst_name);
				goto out;
			} else {
				test_error("setsockopt(TCP_MD5SIG_EXT)");
			}
		} else if (fault(F_POSTINSTALL)) {
			test_fail("%s: post setsockopt() was expected to fail", tst_name);
			goto out;
		}
	}

	if (strategy & POSTINSTALL_AO) {
		if (test_set_ao(sk, ao_password, 0, ao_addr,
				ao_prefix, sndid, rcvid)) {
			if (fault(F_POSTINSTALL)) {
				test_ok("%s: postfailed as expected", tst_name);
				goto out;
			} else {
				test_error("setsockopt(TCP_AO)");
			}
		} else if (fault(F_POSTINSTALL)) {
			test_fail("%s: post setsockopt() was expected to fail", tst_name);
			goto out;
		}
	}

out:
	synchronize_threads(); /* close() */
out_no_sync:
	/* _test_connect_socket() cleans up on failure */
	if (ret > 0)
		close(sk);
}

static void client_add_ip(union tcp_addr *client, const char *ip)
{
	int family = TEST_FAMILY;

	if (inet_pton(family, ip, client) != 1)
		test_error("Can't convert ip address %s", ip);

	if (ip_addr_add(veth_name, family, *client, TEST_PREFIX))
		test_error("Failed to add ip address");
	if (ip_route_add(veth_name, family, *client, this_ip_dest))
		test_error("Failed to add route");
}

static void client_add_ips(void)
{
	client_add_ip(&client2, __TEST_CLIENT_IP(2));
	client_add_ip(&client3, __TEST_CLIENT_IP(3));
	synchronize_threads(); /* server_add_routes() */
}

static void client_add_fail_tests(unsigned int *port)
{
	try_to_add("TCP-AO established: add TCP-MD5 key",
		   (*port)++, POSTINSTALL_MD5 | PREINSTALL_AO,
		   this_ip_dest, TEST_PREFIX, this_ip_dest, TEST_PREFIX,
		   100, 100, true, F_POSTINSTALL);
	try_to_add("TCP-MD5 established: add TCP-AO key",
		   (*port)++, PREINSTALL_MD5 | POSTINSTALL_AO,
		   this_ip_dest, TEST_PREFIX, this_ip_dest, TEST_PREFIX,
		   100, 100, true, F_POSTINSTALL);
	try_to_add("non-signed established: add TCP-AO key",
		   (*port)++, POSTINSTALL_AO,
		   this_ip_dest, TEST_PREFIX, this_ip_dest, TEST_PREFIX,
		   100, 100, false, F_POSTINSTALL);

	try_to_add("TCP-AO key intersects with TCP-MD5 key",
		   (*port), PREINSTALL_MD5 | PREINSTALL_AO,
		   this_ip_addr, TEST_PREFIX, this_ip_addr, TEST_PREFIX,
		   100, 100, true, F_PREINSTALL);
}

static void *client_fn(void *arg)
{
	unsigned int port = test_server_port;
	union tcp_addr addr_any = {};

	client_add_ips();

	try_connect("AO server (INADDR_ANY): AO client", port++, NULL, 0,
		    &addr_any, 0, 100, 100, 0, false, &this_ip_addr);
	try_connect("AO server (INADDR_ANY): MD5 client", port++, &addr_any, 0,
		    NULL, 0, 100, 100, F_TIMEOUT, true, &this_ip_addr);
	try_connect("AO server (INADDR_ANY): unsigned client", port++, NULL, 0,
		    NULL, 0, 100, 100, F_TIMEOUT, false, &this_ip_addr);

	try_connect("MD5 server (INADDR_ANY): AO client", port++, NULL, 0,
		   &addr_any, 0, 100, 100, F_TIMEOUT, true, &this_ip_addr);
	try_connect("MD5 server (INADDR_ANY): MD5 client", port++, &addr_any, 0,
		   NULL, 0, 100, 100, 0, true, &this_ip_addr);
	try_connect("MD5 server (INADDR_ANY): no sign client", port++, NULL, 0,
		   NULL, 0, 100, 100, F_TIMEOUT, true, &this_ip_addr);

	try_connect("no sign server: AO client", port++, NULL, 0,
		   &addr_any, 0, 100, 100, F_TIMEOUT, false, &this_ip_addr);
	try_connect("no sign server: MD5 client", port++, &addr_any, 0,
		   NULL, 0, 100, 100, F_TIMEOUT, true, &this_ip_addr);
	try_connect("no sign server: no sign client", port++, NULL, 0,
		   NULL, 0, 100, 100, 0, false, &this_ip_addr);

	try_connect("AO+MD5 server: AO client (matching)", port++, NULL, 0,
		   &addr_any, 0, 100, 100, 0, true, &client2);
	try_connect("AO+MD5 server: AO client (misconfig, matching MD5)",
		   port++, NULL, 0, &addr_any, 0, 100, 100,
		   F_TIMEOUT, true, &this_ip_addr);
	try_connect("AO+MD5 server: AO client (misconfig, non-matching)",
		   port++, NULL, 0, &addr_any, 0, 100, 100,
		   F_TIMEOUT, true, &client3);
	try_connect("AO+MD5 server: MD5 client (matching)", port++, &addr_any, 0,
		   NULL, 0, 100, 100, 0, true, &this_ip_addr);
	try_connect("AO+MD5 server: MD5 client (misconfig, matching AO)",
		   port++, &addr_any, 0, NULL, 0, 100, 100, F_TIMEOUT,
		   true, &client2);
	try_connect("AO+MD5 server: MD5 client (misconfig, non-matching)",
		   port++, &addr_any, 0, NULL, 0, 100, 100, F_TIMEOUT,
		   true, &client3);
	try_connect("AO+MD5 server: no sign client (unmatched)",
		   port++, NULL, 0, NULL, 0, 100, 100, 0, true, &client3);
	try_connect("AO+MD5 server: no sign client (misconfig, matching AO)",
		   port++, NULL, 0, NULL, 0, 100, 100, F_TIMEOUT,
		   true, &client2);
	try_connect("AO+MD5 server: no sign client (misconfig, matching MD5)",
		   port++, NULL, 0, NULL, 0, 100, 100, F_TIMEOUT,
		   true, &this_ip_addr);

	try_connect("AO+MD5 server: client with both [TCP-MD5] and TCP-AO keys",
		   port++, &this_ip_addr, TEST_PREFIX,
		   &client2, TEST_PREFIX, 100, 100, F_KEYREJECT,
		   true, &this_ip_addr);
	try_connect("AO+MD5 server: client with both TCP-MD5 and [TCP-AO] keys",
		   port++, &this_ip_addr, TEST_PREFIX,
		   &client2, TEST_PREFIX, 100, 100, F_KEYREJECT, true, &client2);

	client_add_fail_tests(&port);

	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(42, server_fn, client_fn);
	return 0;
}
