// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "../../../../include/linux/kernel.h"
#include "aolib.h"

static void clean_ao(int sk, struct tcp_ao *ao)
{
	struct tcp_ao_del ao_del = {};

	ao_del.tcpa_sndid = ao->tcpa_sndid;
	ao_del.tcpa_rcvid = ao->tcpa_rcvid;
	ao_del.tcpa_prefix = ao->tcpa_prefix;
	memcpy(&ao_del.tcpa_addr, &ao->tcpa_addr, sizeof(ao->tcpa_addr));

	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_DEL, &ao_del, sizeof(ao_del)))
		test_error("setsockopt(TCP_AO_DEL) failed to clean");
	close(sk);
}

static void setsockopt_checked(int sk, int optname, struct tcp_ao *ao,
			       int err, const char *tst)
{
	int ret;

	errno = 0;
	ret = setsockopt(sk, IPPROTO_TCP, optname, ao, sizeof(*ao));
	if (ret == -1) {
		if (errno == err) {
			test_ok("%s", tst);
			return;
		}
		test_fail("%s: setsockopt() returned %d", tst, err);
		return;
	}

	if (err) {
		test_fail("%s: setsockopt() was expected to fail with %d", tst, err);
	} else {
		test_ok("%s", tst);
		test_verify_socket_ao(sk, ao);
	}
	clean_ao(sk, ao);
}

static int prepare_defs(struct tcp_ao *ao)
{
	int sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);

	if (sk < 0)
		test_error("socket()");

	if (test_prepare_def_ao(ao, "password", 0, this_ip_dest, -1, 100, 100))
		test_error("prepare default tcp_ao");

	return sk;
}

static void test_extend(void)
{
	struct tcp_ao ao = {};
	struct {
		struct tcp_ao ao;
		char *extend[100];
	} ao_big = {};
	int ret, sk;

	sk = prepare_defs(&ao);
	errno = 0;
	ret = setsockopt(sk, IPPROTO_TCP, TCP_AO,
			&ao, offsetof(struct tcp_ao, tcpa_key));
	if (!ret) {
		test_fail("minminum size: accepted invalid size");
		clean_ao(sk, &ao);
	} else if (errno != EINVAL) {
		test_fail("minminum size: failed with %d", errno);
	} else {
		test_ok("minimum size");
	}

	sk = prepare_defs(&ao_big.ao);
	errno = 0;
	ret = setsockopt(sk, IPPROTO_TCP, TCP_AO, &ao_big.ao, sizeof(ao_big));
	if (ret) {
		test_fail("extended size: returned %d", ret);
	} else {
		test_ok("extended size");
		clean_ao(sk, &ao_big.ao);
	}
}

static void einval_tests(void)
{
	struct tcp_ao ao = {};
	int sk;

	sk = prepare_defs(&ao);
	strcpy(ao.tcpa_alg_name, "imaginary hash algo");
	setsockopt_checked(sk, TCP_AO, &ao, ENOENT, "bad algo");

	sk = prepare_defs(&ao);
	ao.tcpa_flags = (uint16_t)(-1);
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "bad ao flags");

	sk = prepare_defs(&ao);
	ao.tcpa_prefix = 0;
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "empty prefix");

	sk = prepare_defs(&ao);
	ao.tcpa_prefix = 32;
	memcpy(&ao.tcpa_addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "prefix, any addr");

	sk = prepare_defs(&ao);
	ao.tcpa_prefix = 0;
	memcpy(&ao.tcpa_addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	setsockopt_checked(sk, TCP_AO, &ao, 0, "no prefix, any addr");

	sk = prepare_defs(&ao);
	ao.tcpa_prefix = 2;
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "too short prefix");

	sk = prepare_defs(&ao);
	ao.tcpa_prefix = 129;
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "too big prefix");

	sk = prepare_defs(&ao);
	ao.tcpa_maclen = 100;
	setsockopt_checked(sk, TCP_AO, &ao, EMSGSIZE, "too big maclen");

	sk = prepare_defs(&ao);
	ao.tcpa_keyflags = (uint8_t)(-1);
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "bad key flags");

	sk = prepare_defs(&ao);
	ao.tcpa_keylen = TCP_AO_MAXKEYLEN + 1;
	setsockopt_checked(sk, TCP_AO, &ao, EINVAL, "too big keylen");
}

static void duplicate_tests(void)
{
	union tcp_addr network_dup;
	struct tcp_ao ao = {}, ao2 = {};
	int sk;

	sk = prepare_defs(&ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO, &ao, sizeof(ao)))
		test_error("setsockopt()");
	setsockopt_checked(sk, TCP_AO, &ao, EEXIST, "duplicate: full copy");

	sk = prepare_defs(&ao);
	ao2 = ao;
	memcpy(&ao2.tcpa_addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	ao2.tcpa_prefix = 0;
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO, &ao2, sizeof(ao)))
		test_error("setsockopt()");
	setsockopt_checked(sk, TCP_AO, &ao, EEXIST, "duplicate: any addr key on the socket");

	sk = prepare_defs(&ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO, &ao, sizeof(ao)))
		test_error("setsockopt()");
	memcpy(&ao.tcpa_addr, &SOCKADDR_ANY, sizeof(SOCKADDR_ANY));
	ao.tcpa_prefix = 0;
	setsockopt_checked(sk, TCP_AO, &ao, EEXIST, "duplicate: add any addr key");


	if (inet_pton(TEST_FAMILY, TEST_NETWORK, &network_dup) != 1)
		test_error("Can't convert ip address %s", TEST_NETWORK);
	sk = prepare_defs(&ao);
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO, &ao, sizeof(ao)))
		test_error("setsockopt()");
	if (test_prepare_def_ao(&ao, "password", 0, network_dup, 16, 100, 100))
		test_error("prepare default tcp_ao");
	setsockopt_checked(sk, TCP_AO, &ao, EEXIST, "duplicate: add any addr for the same subnet");
}


static void *client_fn(void *arg)
{
	test_extend();
	einval_tests();
	duplicate_tests();

	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(16, client_fn, NULL);
	return 0;
}
