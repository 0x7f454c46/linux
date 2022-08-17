// SPDX-License-Identifier: GPL-2.0
/* Author: Dmitry Safonov <dima@arista.com> */
#include <inttypes.h>
#include "aolib.h"

typedef uint8_t fault_t;
#define F_TIMEOUT	1
#define F_KEYREJECT	2

#define fault(type)	(inj == type)

static void try_accept(const char *tst_name, unsigned int port, const char *pwd,
		       union tcp_addr addr, uint8_t prefix,
		       uint8_t sndid, uint8_t rcvid,
		       const char *cnt_name, uint8_t cnt_expected,
		       fault_t inj)
{
	struct tcp_ao_counters ao_cnt1, ao_cnt2;
	uint64_t before_cnt = 0, after_cnt = 0; /* silence GCC */
	int lsk, err, sk = 0;
	time_t timeout;

	lsk = test_listen_socket(this_ip_addr, port, 1);

	if (pwd && test_add_key(lsk, pwd, addr, prefix, sndid, rcvid))
		test_error("setsockopt(TCP_AO_ADD_KEY)");

	if (cnt_name)
		before_cnt = netstat_get_one(cnt_name, NULL);
	if (pwd && test_get_tcp_ao_counters(lsk, &ao_cnt1, addr,
					    prefix, sndid, rcvid))
		test_error("test_get_tcp_ao_counters()");

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

	if (pwd && test_get_tcp_ao_counters(lsk, &ao_cnt2, addr,
					    prefix, sndid, rcvid))
		test_error("test_get_tcp_ao_counters()");

	close(lsk);
	if (pwd)
		test_tcp_ao_counters_cmp(&ao_cnt1, &ao_cnt2, cnt_expected);

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

static void *server_fn(void *arg)
{
	union tcp_addr wrong_addr, network_addr;
	unsigned int port = test_server_port;

	if (inet_pton(TEST_FAMILY, TEST_WRONG_IP, &wrong_addr) != 1)
		test_error("Can't convert ip address %s", TEST_WRONG_IP);

	try_accept("Non-AO server + AO client", port++, NULL,
		   this_ip_dest, -1, 100, 100,
		   "TCPAOKeyNotFound", 0, F_TIMEOUT);

	try_accept("AO server + Non-AO client", port++, "password",
		   this_ip_dest, -1, 100, 100,
		   "TCPAORequired", TEST_CNT_AO_REQUIRED, F_TIMEOUT);

	try_accept("Wrong password", port++, "password2",
		   this_ip_dest, -1, 100, 100,
		   "TCPAOBad", TEST_CNT_BAD, F_TIMEOUT);

	try_accept("Wrong rcv id", port++, "password",
		   this_ip_dest, -1, 100, 101,
		   "TCPAOKeyNotFound", TEST_CNT_AO_KEY_NOT_FOUND, F_TIMEOUT);

	try_accept("Wrong snd id", port++, "password",
		   this_ip_dest, -1, 101, 100,
		   "TCPAOGood", TEST_CNT_GOOD, F_TIMEOUT);

	try_accept("Server: Wrong addr", port++, "password",
		   wrong_addr, -1, 100, 100,
		   "TCPAOKeyNotFound", TEST_CNT_AO_KEY_NOT_FOUND, F_TIMEOUT);

	try_accept("Client: Wrong addr", port++, NULL,
		   this_ip_dest, -1, 100, 100, NULL, 0, F_TIMEOUT);

	try_accept("rcv id != snd id", port++, "password",
		   this_ip_dest, -1, 200, 100,
		   "TCPAOGood", TEST_CNT_GOOD, 0);

	if (inet_pton(TEST_FAMILY, TEST_NETWORK, &network_addr) != 1)
		test_error("Can't convert ip address %s", TEST_NETWORK);

	try_accept("Server: prefix match", port++, "password",
		   network_addr, 16, 100, 100,
		   "TCPAOGood", TEST_CNT_GOOD, 0);

	try_accept("Client: prefix match", port++, "password",
		   this_ip_dest, -1, 100, 100,
		   "TCPAOGood", TEST_CNT_GOOD, 0);

	/* client exits */
	synchronize_threads();
	return NULL;
}

static void try_connect(const char *tst_name, unsigned int port,
			const char *pwd, union tcp_addr addr, uint8_t prefix,
			uint8_t sndid, uint8_t rcvid,
			uint8_t cnt_expected, fault_t inj)
{
	struct tcp_ao_counters ao_cnt1, ao_cnt2;
	time_t timeout;
	int sk, ret;

	sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		test_error("socket()");

	if (pwd && test_add_key(sk, pwd, addr, prefix, sndid, rcvid))
		test_error("setsockopt(TCP_AO_ADD_KEY)");

	if (pwd && test_get_tcp_ao_counters(sk, &ao_cnt1, addr,
					    prefix, sndid, rcvid))
		test_error("test_get_tcp_ao_counters()");

	synchronize_threads(); /* preparations done */

	timeout = fault(F_TIMEOUT) ? TEST_RETRANSMIT_SEC : TEST_TIMEOUT_SEC;
	ret = _test_connect_socket(sk, this_ip_dest, port, timeout);

	if (ret < 0) {
		if (fault(F_KEYREJECT) && ret == -EKEYREJECTED) {
			test_ok("%s: connect() was prevented", tst_name);
		} else if (ret == -ECONNREFUSED &&
				(fault(F_TIMEOUT) || fault(F_KEYREJECT))) {
			test_ok("%s: refused to connect", tst_name);
		} else {
			test_error("%s: connect() returned %d", tst_name, ret);
		}
		goto out;
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
	if (pwd && ret > 0) {
		if (test_get_tcp_ao_counters(sk, &ao_cnt2, addr,
					     prefix, sndid, rcvid))
			test_error("test_get_tcp_ao_counters()");
		test_tcp_ao_counters_cmp(&ao_cnt1, &ao_cnt2, cnt_expected);
	}
out:
	synchronize_threads(); /* close() */

	if (ret > 0)
		close(sk);
}

static void *client_fn(void *arg)
{
	union tcp_addr wrong_addr, network_addr;
	unsigned int port = test_server_port;

	if (inet_pton(TEST_FAMILY, TEST_WRONG_IP, &wrong_addr) != 1)
		test_error("Can't convert ip address %s", TEST_WRONG_IP);

	try_connect("Non-AO server + AO client", port++, "password",
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("AO server + Non-AO client", port++, NULL,
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("Wrong password", port++, "password",
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("Wrong rcv id", port++, "password",
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("Wrong snd id", port++, "password",
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("Server: Wrong addr", port++, "password",
			this_ip_dest, -1, 100, 100, 0, F_TIMEOUT);

	try_connect("Client: Wrong addr", port++, "password",
			wrong_addr, -1, 100, 100, 0, F_KEYREJECT);

	try_connect("rcv id != snd id", port++, "password",
			this_ip_dest, -1, 100, 200, TEST_CNT_GOOD, 0);

	if (inet_pton(TEST_FAMILY, TEST_NETWORK, &network_addr) != 1)
		test_error("Can't convert ip address %s", TEST_NETWORK);

	try_connect("Server: prefix match", port++, "password",
			this_ip_dest, -1, 100, 100, TEST_CNT_GOOD, 0);

	try_connect("Client: prefix match", port++, "password",
			network_addr, 16, 100, 100, TEST_CNT_GOOD, 0);

	return NULL;
}

int main(int argc, char *argv[])
{
	test_init(19, server_fn, client_fn);
	return 0;
}
