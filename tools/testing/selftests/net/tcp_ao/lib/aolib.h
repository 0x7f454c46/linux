/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TCP-AO selftest library. Provides helpers to unshare network
 * namespaces, create veth, assign ip addresses, set routes,
 * manipulate socket options, read network counter and etc.
 * Author: Dmitry Safonov <dima@arista.com>
 */
#ifndef _AOLIB_H_
#define _AOLIB_H_

#include <arpa/inet.h>
#include <errno.h>
#include <linux/snmp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../../../../include/linux/stringify.h"

/* Working around ksft, see the comment in lib/setup.c */
extern void __test_msg(const char *buf);
extern void __test_ok(const char *buf);
extern void __test_fail(const char *buf);
extern void __test_error(const char *buf);
extern void __test_skip(const char *buf);

__attribute__((__format__(__printf__, 2, 3)))
static inline void __test_print(void (*fn)(const char *), const char *fmt, ...)
{
#define TEST_MSG_BUFFER_SIZE 4096
	char buf[TEST_MSG_BUFFER_SIZE];
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(buf, sizeof(buf), fmt, arg);
	va_end(arg);
	fn(buf);
}

#define test_print(fmt, ...)						\
	__test_print(__test_msg, "%ld[%s:%u] " fmt "\n",		\
		     syscall(SYS_gettid),				\
		     __FILE__, __LINE__, ##__VA_ARGS__)

#define test_ok(fmt, ...)						\
	__test_print(__test_ok, fmt "\n", ##__VA_ARGS__)
#define test_skip(fmt, ...)						\
	__test_print(__test_skip, fmt "\n", ##__VA_ARGS__)

#define test_fail(fmt, ...)						\
do {									\
	if (errno)							\
		__test_print(__test_fail, fmt ": %m\n", ##__VA_ARGS__);	\
	else								\
		__test_print(__test_fail, fmt "\n", ##__VA_ARGS__);	\
	test_failed();							\
} while (0)

#define KSFT_FAIL  1
#define test_error(fmt, ...)						\
do {									\
	if (errno)							\
		__test_print(__test_error, "%ld[%s:%u] " fmt ": %m\n",	\
			     syscall(SYS_gettid), __FILE__, __LINE__,	\
			     ##__VA_ARGS__);				\
	else								\
		__test_print(__test_error, "%ld[%s:%u] " fmt "\n",	\
			     syscall(SYS_gettid), __FILE__, __LINE__,	\
			     ##__VA_ARGS__);				\
	exit(KSFT_FAIL);						\
} while (0)

union tcp_addr {
	struct in_addr a4;
	struct in6_addr a6;
};

typedef void *(*thread_fn)(void *);
extern void test_failed(void);
extern void __test_init(unsigned int ntests, int family, unsigned int prefix,
			union tcp_addr addr1, union tcp_addr addr2,
			thread_fn peer1, thread_fn peer2);

static inline void test_init2(unsigned int ntests,
			      thread_fn peer1, thread_fn peer2,
			      int family, unsigned int prefix,
			      const char *addr1, const char *addr2)
{
	union tcp_addr taddr1, taddr2;

	if (inet_pton(family, addr1, &taddr1) != 1)
		test_error("Can't convert ip address %s", addr1);
	if (inet_pton(family, addr2, &taddr2) != 1)
		test_error("Can't convert ip address %s", addr2);

	__test_init(ntests, family, prefix, taddr1, taddr2, peer1, peer2);
}
extern void test_add_destructor(void (*d)(void));
extern void test_set_optmem(size_t value);

extern const struct sockaddr_in6 addr_any6;
extern const struct sockaddr_in addr_any4;

#ifdef IPV6_TEST
# define __TEST_CLIENT_IP(n)	("2001:db8:" __stringify(n) "::1")
# define TEST_CLIENT_IP	__TEST_CLIENT_IP(1)
# define TEST_WRONG_IP	"2001:db8:253::1"
# define TEST_SERVER_IP	"2001:db8:254::1"
# define TEST_NETWORK	"2001::"
# define TEST_PREFIX	128
# define TEST_FAMILY	AF_INET6
# define SOCKADDR_ANY	addr_any6
#else
# define __TEST_CLIENT_IP(n)	("10.0." __stringify(n) ".1")
# define TEST_CLIENT_IP	__TEST_CLIENT_IP(1)
# define TEST_WRONG_IP	"10.0.253.1"
# define TEST_SERVER_IP	"10.0.254.1"
# define TEST_NETWORK	"10.0.0.0"
# define TEST_PREFIX	32
# define TEST_FAMILY	AF_INET
# define SOCKADDR_ANY	addr_any4
#endif

static inline void test_init(unsigned int ntests,
			     thread_fn peer1, thread_fn peer2)
{
	test_init2(ntests, peer1, peer2, TEST_FAMILY, TEST_PREFIX,
			TEST_SERVER_IP, TEST_CLIENT_IP);
}
extern void synchronize_threads(void);
extern void switch_ns(int fd);

extern __thread union tcp_addr this_ip_addr;
extern __thread union tcp_addr this_ip_dest;
extern int test_family;

extern void randomize_buffer(void *buf, size_t buflen);
extern const char veth_name[];
extern int add_veth(const char *name, int nsfda, int nsfdb);
extern int ip_addr_add(const char *intf, int family,
		       union tcp_addr addr, uint8_t prefix);
extern int ip_route_add(const char *intf, int family,
			union tcp_addr src, union tcp_addr dst);
extern int link_set_up(const char *intf);

extern const unsigned int test_server_port;
extern int test_wait_fd(int sk, time_t sec, bool write);
extern int __test_connect_socket(int sk, void *addr, size_t addr_sz,
				 time_t timeout);
extern int __test_listen_socket(int backlog, void *addr, size_t addr_sz);

static inline int test_listen_socket(const union tcp_addr taddr,
				     unsigned int port, int backlog)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(port),
		.sin6_addr	= taddr.a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= htons(port),
		.sin_addr	= taddr.a4,
	};
#endif
	return __test_listen_socket(backlog, (void *)&addr, sizeof(addr));
}

#ifndef DEFAULT_TEST_ALGO
#define DEFAULT_TEST_ALGO	"cmac(aes128)"
#endif

#ifdef IPV6_TEST
#define DEFAULT_TEST_PREFIX	128
#else
#define DEFAULT_TEST_PREFIX	32
#endif

/*
 * Timeout on syscalls where failure is not expected.
 * You may want to rise it if the test machine is very busy.
 */
#ifndef TEST_TIMEOUT_SEC
#define TEST_TIMEOUT_SEC	5
#endif

/*
 * Timeout on connect() where a failure is expected.
 * If set to 0 - kernel will try to retransmit SYN number of times, set in
 * /proc/sys/net/ipv4/tcp_syn_retries
 * By default set to 1 to make tests pass faster on non-busy machine.
 */
#ifndef TEST_RETRANSMIT_SEC
#define TEST_RETRANSMIT_SEC	1
#endif


static inline int _test_connect_socket(int sk, const union tcp_addr taddr,
				       unsigned int port, time_t timeout)
{
#ifdef IPV6_TEST
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(port),
		.sin6_addr	= taddr.a6,
	};
#else
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= htons(port),
		.sin_addr	= taddr.a4,
	};
#endif
	return __test_connect_socket(sk, (void *)&addr, sizeof(addr), timeout);
}

static inline int test_connect_socket(int sk, const union tcp_addr taddr,
				      unsigned int port)
{
	return _test_connect_socket(sk, taddr, port, TEST_TIMEOUT_SEC);
}

extern int test_prepare_ao_sockaddr(struct tcp_ao *ao,
		const char *alg, uint16_t flags,
		void *addr, size_t addr_sz, uint8_t prefix,
		uint8_t sndid, uint8_t rcvid, uint8_t maclen,
		uint8_t keyflags, uint8_t keylen, const char *key);

static inline int test_prepare_ao(struct tcp_ao *ao,
		const char *alg, uint16_t flags,
		union tcp_addr in_addr, uint8_t prefix,
		uint8_t sndid, uint8_t rcvid, uint8_t maclen,
		uint8_t keyflags, uint8_t keylen, const char *key)
{
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

	return test_prepare_ao_sockaddr(ao, alg, flags,
			(void *)&addr, sizeof(addr), prefix, sndid, rcvid,
			maclen, keyflags, keylen, key);
}

static inline int test_prepare_def_ao(struct tcp_ao *ao,
		const char *key, uint16_t flags,
		union tcp_addr in_addr, uint8_t prefix,
		uint8_t sndid, uint8_t rcvid)
{
	if (prefix > DEFAULT_TEST_PREFIX)
		prefix = DEFAULT_TEST_PREFIX;

	return test_prepare_ao(ao, DEFAULT_TEST_ALGO, flags, in_addr,
			prefix, sndid, rcvid, 0, 0, strlen(key), key);
}

extern int test_get_one_ao(int sk, struct tcp_ao_getsockopt *out,
			   uint16_t flags, void *addr, size_t addr_sz,
			   uint8_t prefix, uint8_t sndid, uint8_t rcvid);
extern int test_cmp_getsockopt_setsockopt(const struct tcp_ao *a,
					  const struct tcp_ao_getsockopt *b);

static inline int test_verify_socket_ao(int sk, struct tcp_ao *ao)
{
	struct tcp_ao_getsockopt tmp = {};
	int err;

	err = test_get_one_ao(sk, &tmp, 0, &ao->tcpa_addr,
			sizeof(ao->tcpa_addr), ao->tcpa_prefix,
			ao->tcpa_sndid, ao->tcpa_rcvid);
	if (err)
		return err;

	return test_cmp_getsockopt_setsockopt(ao, &tmp);
}

static inline int test_set_ao(int sk, const char *key, uint16_t flags,
			      union tcp_addr in_addr, uint8_t prefix,
			      uint8_t sndid, uint8_t rcvid)
{
	struct tcp_ao tmp = {};
	int err;

	err = test_prepare_def_ao(&tmp, key, flags, in_addr,
			prefix, sndid, rcvid);
	if (err)
		return err;

	if (setsockopt(sk, IPPROTO_TCP, TCP_AO, &tmp, sizeof(tmp)) < 0)
		return -errno;

	return test_verify_socket_ao(sk, &tmp);
}

extern ssize_t test_server_run(int sk, ssize_t quota, time_t timeout_sec);
extern ssize_t test_client_loop(int sk, char *buf, size_t buf_sz,
				const size_t msg_len, time_t timeout_sec);
extern int test_client_verify(int sk, const size_t msg_len, const size_t nr,
			      time_t timeout_sec);

struct netstat;
extern struct netstat *netstat_read(void);
extern void netstat_free(struct netstat *ns);
extern void netstat_print_diff(struct netstat *nsa, struct netstat *nsb);
extern uint64_t netstat_get(struct netstat *ns,
			    const char *name, bool *not_found);

static inline uint64_t netstat_get_one(const char *name, bool *not_found)
{
	struct netstat *ns = netstat_read();
	uint64_t ret;

	ret = netstat_get(ns, name, not_found);

	netstat_free(ns);
	return ret;
}

#endif /* _AOLIB_H_ */
