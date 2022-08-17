// SPDX-License-Identifier: GPL-2.0
#include <alloca.h>
#include <fcntl.h>
#include <string.h>
#include "../../../../../include/linux/kernel.h"
#include "../../../../../include/linux/stringify.h"
#include "aolib.h"

const unsigned int test_server_port = 7010;
int __test_listen_socket(int backlog, void *addr, size_t addr_sz)
{
	int err, sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	long flags;

	if (sk < 0)
		test_error("socket()");

	err = setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, veth_name,
			 strlen(veth_name) + 1);
	if (err < 0)
		test_error("setsockopt(SO_BINDTODEVICE)");

	if (bind(sk, (struct sockaddr *)addr, addr_sz) < 0)
		test_error("bind()");

	flags = fcntl(sk, F_GETFL);
	if ((flags < 0) || (fcntl(sk, F_SETFL, flags | O_NONBLOCK) < 0))
		test_error("fcntl()");

	if (listen(sk, backlog))
		test_error("listen()");

	return sk;
}

int test_wait_fd(int sk, time_t sec, bool write)
{
	struct timeval tv = { .tv_sec = sec };
	struct timeval *ptv = NULL;
	fd_set fds, efds;
	int ret;
	socklen_t slen = sizeof(ret);

	FD_ZERO(&fds);
	FD_SET(sk, &fds);
	FD_ZERO(&efds);
	FD_SET(sk, &efds);

	if (sec)
		ptv = &tv;

	errno = 0;
	if (write)
		ret = select(sk + 1, NULL, &fds, &efds, ptv);
	else
		ret = select(sk + 1, &fds, NULL, &efds, ptv);
	if (ret <= 0)
		return -errno;

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &slen) || ret)
		return -ret;
	return sk;
}

int __test_connect_socket(int sk, void *addr, size_t addr_sz, time_t timeout)
{
	long flags;
	int err;

	err = setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, veth_name,
			 strlen(veth_name) + 1);
	if (err < 0)
		test_error("setsockopt(SO_BINDTODEVICE)");

	if (!timeout) {
		err = connect(sk, addr, addr_sz);
		if (err) {
			err = -errno;
			goto out;
		}
		return 0;
	}

	flags = fcntl(sk, F_GETFL);
	if ((flags < 0) || (fcntl(sk, F_SETFL, flags | O_NONBLOCK) < 0))
		test_error("fcntl()");

	if (connect(sk, addr, addr_sz) < 0) {
		if (errno != EINPROGRESS) {
			err = -errno;
			goto out;
		}
		err = test_wait_fd(sk, timeout, 1);
		if (err <= 0)
			goto out;
	}
	return sk;

out:
	close(sk);
	return err;
}

int test_prepare_ao_sockaddr(struct tcp_ao *ao, const char *alg, uint16_t flags,
		void *addr, size_t addr_sz, uint8_t prefix,
		uint8_t sndid, uint8_t rcvid, uint8_t maclen,
		uint8_t keyflags, uint8_t keylen, const char *key)
{
	memset(ao, 0, sizeof(struct tcp_ao));

	ao->tcpa_flags		= flags;
	ao->tcpa_prefix		= prefix;
	ao->tcpa_sndid		= sndid;
	ao->tcpa_rcvid		= rcvid;
	ao->tcpa_maclen		= maclen;
	ao->tcpa_keyflags	= keyflags;
	ao->tcpa_keylen		= keylen;

	memcpy(&ao->tcpa_addr, addr, addr_sz);

	if (strlen(alg) > 64)
		return -ENOBUFS;
	strncpy(ao->tcpa_alg_name, alg, 64);

	memcpy(ao->tcpa_key, key,
	       (keylen > TCP_AO_MAXKEYLEN ) ? TCP_AO_MAXKEYLEN : keylen);
	return 0;
}

int test_get_one_ao(int sk, struct tcp_ao_getsockopt *out, uint16_t flags,
		void *addr, size_t addr_sz, uint8_t prefix,
		uint8_t sndid, uint8_t rcvid)
{
	struct tcp_ao_getsockopt tmp = {};
	socklen_t tmp_sz = sizeof(tmp);
	int ret;

	memcpy(&tmp.addr, addr, addr_sz);
	tmp.prefix = prefix;
	tmp.sndid  = sndid;
	tmp.rcvid  = rcvid;
	tmp.flags  = flags;
	tmp.nkeys  = 1;

	ret = getsockopt(sk, IPPROTO_TCP, TCP_AO_GET, &tmp, &tmp_sz);
	if (ret)
		return ret;
	if (tmp.nkeys != 1)
		return -ENOENT;
	*out = tmp;
	return 0;
}

int test_cmp_getsockopt_setsockopt(const struct tcp_ao *a,
				   const struct tcp_ao_getsockopt *b)
{
	bool is_kdf_aes_128_cmac = false;

	if (!strcmp("cmac(aes128)", a->tcpa_alg_name))
		is_kdf_aes_128_cmac = (a->tcpa_keylen != 16);

#define __cmp_ao(member)						\
	if (b->member != a->tcpa_##member) {				\
		test_fail("getsockopt(): " __stringify(member) " %u != %u",	\
				b->member, a->tcpa_##member);		\
		return -1;						\
	}
	__cmp_ao(sndid);
	__cmp_ao(rcvid);
	__cmp_ao(prefix);
	__cmp_ao(keyflags);
	if (a->tcpa_maclen) {
		__cmp_ao(maclen);
	} else if (b->maclen != 12) {
		test_fail("getsockopt(): expected default maclen 12, but it's %u",
				b->maclen);
		return -1;
	}
	if (!is_kdf_aes_128_cmac) {
		__cmp_ao(keylen);
	} else if (b->keylen != 16) {
		test_fail("getsockopt(): expected keylen 16 for cmac(aes128), but it's %u",
				b->keylen);
		return -1;
	}
#undef __cmp_ao
	if (!is_kdf_aes_128_cmac && memcmp(b->key, a->tcpa_key, a->tcpa_keylen)) {
		test_fail("getsockopt(): returned key is different `%s' != `%s'",
				b->key, a->tcpa_key);
		return -1;
	}
	if (memcmp(&b->addr, &a->tcpa_addr, sizeof(b->addr))) {
		test_fail("getsockopt(): returned address is different");
		return -1;
	}
	if (!is_kdf_aes_128_cmac && strcmp(b->alg_name, a->tcpa_alg_name)) {
		test_fail("getsockopt(): returned algorithm is different");
		return -1;
	}
	if (is_kdf_aes_128_cmac && strcmp(b->alg_name, "cmac(aes)")) {
		test_fail("getsockopt(): returned algorithm is different");
		return -1;
	}
	return 0;
}

#define TEST_BUF_SIZE 4096
ssize_t test_server_run(int sk, ssize_t quota, time_t timeout_sec)
{
	ssize_t total = 0;

	do {
		char buf[TEST_BUF_SIZE];
		ssize_t bytes, sent;
		int ret;

		ret = test_wait_fd(sk, timeout_sec, 0);
		if (ret <= 0)
			return ret;

		bytes = recv(sk, buf, sizeof(buf), 0);

		if (bytes < 0)
			test_error("recv(): %zd", bytes);
		if (bytes == 0)
			break;

		ret = test_wait_fd(sk, timeout_sec, 1);
		if (ret <= 0)
			return ret;

		sent = send(sk, buf, bytes, 0);
		if (sent == 0)
			break;
		if (sent != bytes)
			test_error("send()");
		total += bytes;
	} while (!quota || total < quota);

	return total;
}

ssize_t test_client_loop(int sk, char *buf, size_t buf_sz,
			 const size_t msg_len, time_t timeout_sec)
{
	char msg[msg_len];
	int nodelay = 1;
	size_t i;

	if (setsockopt(sk, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)))
		test_error("setsockopt(TCP_NODELAY)");

	for (i = 0; i < buf_sz; i += min(msg_len, buf_sz - i)) {
		size_t sent, bytes = min(msg_len, buf_sz - i);
		int ret;

		ret = test_wait_fd(sk, timeout_sec, 1);
		if (ret <= 0)
			return ret;

		sent = send(sk, buf + i, bytes, 0);
		if (sent == 0)
			break;
		if (sent != bytes)
			test_error("send()");

		ret = test_wait_fd(sk, timeout_sec, 0);
		if (ret <= 0)
			return ret;

		bytes = recv(sk, msg, sizeof(msg), 0);
		if (bytes < 0)
			test_error("recv(): %zd", bytes);
		if (bytes != sent)
			test_error("recv(): %zd != %zd", bytes, sent);
		if (memcmp(buf + i, msg, bytes) != 0) {
			test_fail("received message differs");
			return -1;
		}
	}
	return i;
}

int test_client_verify(int sk, const size_t msg_len, const size_t nr,
		       time_t timeout_sec)
{
	size_t buf_sz = msg_len * nr;
	char *buf = alloca(buf_sz);

	randomize_buffer(buf, buf_sz);
	if (test_client_loop(sk, buf, buf_sz, msg_len, timeout_sec) != buf_sz)
		return -1;
	return 0;
}
