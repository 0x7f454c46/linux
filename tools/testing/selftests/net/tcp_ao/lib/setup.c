// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include "aolib.h"

/*
 * Can't be included in the header: it defines static variables which
 * will be unique to every object. Let's include it only once here.
 */
#include "../../../kselftest.h"

/* Prevent overriding of one thread's output by another */
static pthread_mutex_t ksft_print_lock = PTHREAD_MUTEX_INITIALIZER;

void __test_msg(const char *buf)
{
	pthread_mutex_lock(&ksft_print_lock);
	ksft_print_msg(buf);
	pthread_mutex_unlock(&ksft_print_lock);
}
void __test_ok(const char *buf)
{
	pthread_mutex_lock(&ksft_print_lock);
	ksft_test_result_pass(buf);
	pthread_mutex_unlock(&ksft_print_lock);
}
void __test_fail(const char *buf)
{
	pthread_mutex_lock(&ksft_print_lock);
	ksft_test_result_fail(buf);
	pthread_mutex_unlock(&ksft_print_lock);
}

void __test_error(const char *buf)
{
	pthread_mutex_lock(&ksft_print_lock);
	ksft_test_result_error(buf);
	pthread_mutex_unlock(&ksft_print_lock);
}

void __test_skip(const char *buf)
{
	pthread_mutex_lock(&ksft_print_lock);
	ksft_test_result_skip(buf);
	pthread_mutex_unlock(&ksft_print_lock);
}

static volatile int failed;
static volatile int skipped;

void test_failed(void)
{
	failed = 1;
}

static void test_exit(void)
{
	if (failed) {
		ksft_exit_fail();
	} else if (skipped) {
		/* ksft_exit_skip() is different from ksft_exit_*() */
		ksft_print_cnts();
		exit(KSFT_SKIP);
	} else {
		ksft_exit_pass();
	}
}

struct dlist_t {
	void (*destruct)(void);
	struct dlist_t *next;
};
static struct dlist_t *destructors_list;

void test_add_destructor(void (*d)(void))
{
	struct dlist_t *p;

	p = malloc(sizeof(struct dlist_t));
	if (p == NULL)
		test_error("malloc() failed");

	p->next = destructors_list;
	p->destruct = d;
	destructors_list = p;
}

static void test_destructor(void) __attribute__((destructor));
static void test_destructor(void)
{
	while (destructors_list) {
		struct dlist_t *p = destructors_list->next;

		destructors_list->destruct();
		free(destructors_list);
		destructors_list = p;
	}
	test_exit();
}

static void sig_int(int signo)
{
	test_error("Caught SIGINT - exiting");
}

static int open_netns(void)
{
	const char *netns_path = "/proc/self/ns/net";
	int fd;

	fd = open(netns_path, O_RDONLY);
	if (fd <= 0)
		test_error("open(%s)", netns_path);
	return fd;
}

static int unshare_open(void)
{
	if (unshare(CLONE_NEWNET) != 0)
		test_error("unshare()");

	return open_netns();
}

void switch_ns(int fd)
{
	if (setns(fd, CLONE_NEWNET))
		test_error("setns()");
}

int switch_save_ns(int new_ns)
{
	int ret = open_netns();

	switch_ns(new_ns);
	return ret;
}

static int nsfd_outside	= -1;
static int nsfd_parent	= -1;
static int nsfd_child	= -1;
const char veth_name[]	= "ktst-veth";

static void init_namespaces(void)
{
	nsfd_outside = open_netns();
	nsfd_parent = unshare_open();
	nsfd_child = unshare_open();
}

static void link_init(const char *veth, int family, uint8_t prefix,
		      union tcp_addr addr, union tcp_addr dest)
{
	if (link_set_up(veth))
		test_error("Failed to set link up");
	if (ip_addr_add(veth, family, addr, prefix))
		test_error("Failed to add ip address");
	if (ip_route_add(veth, family, addr, dest))
		test_error("Failed to add route");
}

static unsigned int nr_threads = 1;

static pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sync_cond = PTHREAD_COND_INITIALIZER;
static volatile unsigned int stage_threads[2];
static volatile unsigned int stage_nr;

/* synchronize all threads in the same stage */
void synchronize_threads(void)
{
	unsigned int q = stage_nr;

	pthread_mutex_lock(&sync_lock);
	stage_threads[q]++;
	if (stage_threads[q] == nr_threads) {
		stage_nr ^= 1;
		stage_threads[stage_nr] = 0;
		pthread_cond_signal(&sync_cond);
	}
	while (stage_threads[q] < nr_threads)
		pthread_cond_wait(&sync_cond, &sync_lock);
	pthread_mutex_unlock(&sync_lock);
}

__thread union tcp_addr this_ip_addr;
__thread union tcp_addr this_ip_dest;
int test_family;

struct new_pthread_arg {
	thread_fn	func;
	union tcp_addr	my_ip;
	union tcp_addr	dest_ip;
};
static void *new_pthread_entry(void *arg)
{
	struct new_pthread_arg *p = arg;

	this_ip_addr = p->my_ip;
	this_ip_dest = p->dest_ip;
	p->func(NULL); /* shouldn't return */
	exit(KSFT_FAIL);
}

static void check_tcp_ao_support(void)
{
	struct sockaddr_in addr = {
		.sin_family = test_family,
	};
	struct tcp_ao_add tmp = {};
	const char *password = "password";
	int sk;

	sk = socket(test_family, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		test_error("socket()");

	tmp.sndid = 100;
	tmp.rcvid = 100;
	tmp.keylen = strlen(password);
	memcpy(tmp.key, password, strlen(password));
	strcpy(tmp.alg_name, "cmac(aes128)");
	memcpy(&tmp.addr, &addr, sizeof(addr));
	if (setsockopt(sk, IPPROTO_TCP, TCP_AO_ADD_KEY, &tmp, sizeof(tmp)) < 0) {
		if (errno == ENOPROTOOPT) {
			ksft_set_plan(1);
			ksft_print_header();
			skipped = 1;
			test_skip("setsockopt(TCP_AO_ADD_KEY) is not supported");
			exit(KSFT_SKIP);
		} else {
			test_error("setsockopt(TCP_AO_ADD_KEY)");
		}
	}
	close(sk);
}

void __test_init(unsigned int ntests, int family, unsigned int prefix,
		 union tcp_addr addr1, union tcp_addr addr2,
		 thread_fn peer1, thread_fn peer2)
{
	struct sigaction sa = {
		.sa_handler = sig_int,
		.sa_flags = SA_RESTART,
	};
	time_t seed = time(NULL);

	test_family = family;
	check_tcp_ao_support();
	ksft_set_plan(ntests);

	test_print("rand seed %u", (unsigned int)seed);
	srand(seed);

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL))
		test_error("Can't set SIGINT handler");

	ksft_print_header();
	init_namespaces();

	if (add_veth(veth_name, nsfd_parent, nsfd_child))
		test_error("Failed to add veth");

	switch_ns(nsfd_child);
	link_init(veth_name, family, prefix, addr2, addr1);
	if (peer2) {
		struct new_pthread_arg targ;
		pthread_t t;

		targ.my_ip = addr2;
		targ.dest_ip = addr1;
		targ.func = peer2;
		nr_threads++;
		if (pthread_create(&t, NULL, new_pthread_entry, &targ))
			test_error("Failed to create pthread");
	}
	switch_ns(nsfd_parent);
	link_init(veth_name, family, prefix, addr1, addr2);

	this_ip_addr = addr1;
	this_ip_dest = addr2;
	peer1(NULL);
	if (failed)
		exit(KSFT_FAIL);
	else
		exit(KSFT_PASS);
}

/* /proc/sys/net/core/optmem_max artifically limits the amount of memory
 * that can be allocated with sock_kmalloc() on each socket in the system.
 * It is not virtualized, so it has to written outside test namespaces.
 * To be nice a test will revert optmem back to the old value.
 * Keeping it simple without any file lock, which means the tests that
 * need to set/increase optmem value shouldn't run in parallel.
 * Also, not re-entrant.
 */
static const char *optmem_file = "/proc/sys/net/core/optmem_max";
static size_t saved_optmem;

static void __test_set_optmem(size_t new, size_t *old)
{
	FILE *foptmem;
	int old_ns;

	old_ns = switch_save_ns(nsfd_outside);
	foptmem = fopen(optmem_file, "r+");
	if (!foptmem)
		test_error("failed to open %s", optmem_file);

	if (old != NULL) {
		if (fscanf(foptmem, "%zu", old) != 1)
			test_error("can't read from %s", optmem_file);
		fclose(foptmem);
		foptmem = fopen(optmem_file, "w");
		if (!foptmem)
			test_error("failed to open %s", optmem_file);
	}

	if (fprintf(foptmem, "%zu", new) <= 0)
		test_error("can't write %zu to %s", new, optmem_file);
	fclose(foptmem);
	switch_ns(old_ns);
}

static void test_revert_optmem(void)
{
	if (saved_optmem == 0)
		return;

	__test_set_optmem(saved_optmem, NULL);
}

void test_set_optmem(size_t value)
{
	if (saved_optmem == 0) {
		__test_set_optmem(value, &saved_optmem);
		test_add_destructor(test_revert_optmem);
	} else {
		__test_set_optmem(value, NULL);
	}
}
