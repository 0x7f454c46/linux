// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "../../../../include/linux/kernel.h"
#include "aolib.h"

static void __setsockopt_checked(int sk, int optname, bool get,
				 void *optval, socklen_t len,
				 int err, const char *tst, const char *tst2)
{
	int ret;

	errno = 0;
	if (get)
		ret = getsockopt(sk, IPPROTO_TCP, optname, optval, &len);
	else
		ret = setsockopt(sk, IPPROTO_TCP, optname, optval, len);
	if (ret == -1) {
		if (errno == err)
			test_ok("%s%s", tst, tst2 ?: "");
		else
			test_fail("%s%s: %setsockopt() failed",
				  tst, tst2 ?: "", get ? "g" : "s");
		close(sk);
		return;
	}

	if (err) {
		test_fail("%s%s: %setsockopt() was expected to fail with %d",
			  tst, tst2 ?: "", get ? "g" : "s", err);
	} else {
		test_ok("%s%s", tst, tst2 ?: "");
		if (optname == TCP_AO_ADD_KEY)
			test_verify_socket_key(sk, optval);
	}
	close(sk);
}

static void setsockopt_checked(int sk, int optname, struct tcp_ao_add *ao,
			       int err, const char *tst)
{
	__setsockopt_checked(sk, optname, false, ao, sizeof(*ao), err, tst, NULL);
}

static int prepare_defs(int cmd, void *optval)
{
	int sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);

	if (sk < 0)
		test_error("socket()");

	switch (cmd) {
	case TCP_AO_ADD_KEY: {
		struct tcp_ao_add *add = optval;

		if (test_prepare_def_key(add, "password", 0, this_ip_dest,
					-1, 0, 100, 100))
			test_error("prepare default tcp_ao_add");
		break;
		}
	case TCP_AO_DEL_KEY: {
		struct tcp_ao_del *del = optval;

		if (test_add_key(sk, "password", this_ip_dest,
				 DEFAULT_TEST_PREFIX, 100, 100))
			test_error("add default key");
		del->sndid = 100;
		del->rcvid = 100;
		del->prefix = DEFAULT_TEST_PREFIX;
		tcp_addr_to_sockaddr_in(&this_ip_dest, 0, (void *)&del->addr);
		break;
		}
	case TCP_AO_INFO: {
		if (test_add_key(sk, "password", this_ip_dest,
				 DEFAULT_TEST_PREFIX, 100, 100))
			test_error("add default key");
		break;
		}
	case TCP_AO_GET_KEYS: {
		struct tcp_ao_getsockopt *get = optval;

		if (test_add_key(sk, "password", this_ip_dest,
				 DEFAULT_TEST_PREFIX, 100, 100))
			test_error("add default key");
		get->nkeys = 1;
		get->get_all = 1;
		break;
		}
	default:
		test_error("unknown cmd");
	}

	return sk;
}

static void test_extend(int cmd, bool get, const char *tst, socklen_t under_size)
{
	struct {
		union {
			struct tcp_ao_add add;
			struct tcp_ao_del del;
			struct tcp_ao_getsockopt get;
			struct tcp_ao_info_opt info;
		};
		char *extend[100];
	} tmp_opt;
	int sk;

	memset(&tmp_opt, 0, sizeof(tmp_opt));
	sk = prepare_defs(cmd, &tmp_opt);
	__setsockopt_checked(sk, cmd, get, &tmp_opt, under_size,
			     EINVAL, tst, ": minimum size");

	memset(&tmp_opt, 0, sizeof(tmp_opt));
	sk = prepare_defs(cmd, &tmp_opt);
	__setsockopt_checked(sk, cmd, get, &tmp_opt, sizeof(tmp_opt),
			     0, tst, ": extended size");
}

static void extend_tests(void)
{
	test_extend(TCP_AO_ADD_KEY, false, "AO add",
		    offsetof(struct tcp_ao_add, key));
	test_extend(TCP_AO_DEL_KEY, false, "AO del",
		    offsetof(struct tcp_ao_del, keyflags));
	test_extend(TCP_AO_INFO, false, "AO set info",
		    offsetof(struct tcp_ao_info_opt, pkt_dropped_icmp));
	test_extend(TCP_AO_INFO, true, "AO get info", -1);
	test_extend(TCP_AO_GET_KEYS, true, "AO get keys", -1);
}

static void einval_tests(void)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 *addr6;
#else
	struct sockaddr_in *addr;
#endif
	struct tcp_ao_add ao = {};
	int sk;

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.keylen = TCP_AO_MAXKEYLEN + 1;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "too big keylen");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.reserved = 1;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "using reserved padding");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.reserved2 = 1;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "using reserved2 padding");
	/* Add tcp_ao_verify_ipv{4,6}() checks */
	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.addr.ss_family = AF_UNIX;
	memcpy(&ao.addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "wrong address family");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
#ifdef IPV6_TEST
	addr6 = (struct sockaddr_in6 *)&ao.addr;
	addr6->sin6_port = 1234;
#else
	addr = (struct sockaddr_in *)&ao.addr;
	addr->sin_port = 1234;
#endif
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "port (unsupported)");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.prefix = 0;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "empty prefix");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.prefix = 32;
	memcpy(&ao.addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "prefix, any addr");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.prefix = 0;
	memcpy(&ao.addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, 0, "no prefix, any addr");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.prefix = 129;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "too big prefix");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.prefix = 2;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "too short prefix");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.keyflags = (uint8_t)(-1);
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "bad key flags");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.ifindex = 42;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL,
			   "ifindex without TCP_AO_KEYF_IFNINDEX");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.keyflags |= TCP_AO_KEYF_IFINDEX;
	ao.ifindex = 42;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EINVAL, "non-existent VRF");
	/* TODO: Add tcp_md5_do_lookup{,_any_l3index}() checks */

	/* tcp_ao_parse_crypto() */
	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao.maclen = 100;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EMSGSIZE, "maclen bigger than TCP hdr");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	strcpy(ao.alg_name, "imaginary hash algo");
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, ENOENT, "bad algo");
}

static void duplicate_tests(void)
{
	union tcp_addr network_dup;
	struct tcp_ao_add ao = {}, ao2 = {};
	int sk;

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)))
		test_error("setsockopt()");
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EEXIST, "duplicate: full copy");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	ao2 = ao;
	memcpy(&ao2.addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	ao2.prefix = 0;
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao2, sizeof(ao)))
		test_error("setsockopt()");
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EEXIST, "duplicate: any addr key on the socket");

	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)))
		test_error("setsockopt()");
	memcpy(&ao.addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	ao.prefix = 0;
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EEXIST, "duplicate: add any addr key");

	if (inet_pton(TEST_FAMILY, TEST_NETWORK, &network_dup) != 1)
		test_error("Can't convert ip address %s", TEST_NETWORK);
	sk = prepare_defs(TCP_AO_ADD_KEY, &ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)))
		test_error("setsockopt()");
	if (test_prepare_def_key(&ao, "password", 0, network_dup,
				 16, 0, 100, 100))
		test_error("prepare default tcp_ao_add");
	setsockopt_checked(sk, TCP_AO_ADD_KEY, &ao, EEXIST, "duplicate: add any addr for the same subnet");
}


static void *client_fn(void *arg)
{
	extend_tests();
	einval_tests();
	duplicate_tests();

	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(29, client_fn, NULL);
	return 0;
}
