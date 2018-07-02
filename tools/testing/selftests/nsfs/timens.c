// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef CLONE_NEWTIME
# define CLONE_NEWTIME	0x00001000
#endif

/*
 * Test shouldn't be run for a day, so add 10 days to child
 * time and check parent's time to be in the same day.
 */
#define DAY_IN_SEC			(60*60*24)
#define TEN_DAYS_IN_SEC			(10*DAY_IN_SEC)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define printk(fmt, lvl, ...)						\
	fprintf(stderr, "[%s] (%s:%d)\t" fmt "\n",			\
			lvl, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_p(func, fmt, ...)	func(fmt ": %m", ##__VA_ARGS__)

#define pr_err(fmt, ...)						\
	printk(fmt, "ERR", ##__VA_ARGS__)
#define pr_warn(fmt, ...)						\
	printk(fmt, "WARN", ##__VA_ARGS__)
#define pr_note(fmt, ...)						\
	printk(fmt, "NOTE", ##__VA_ARGS__)
#define pr_fail(fmt, ...)						\
	printk(fmt, "FAIL", ##__VA_ARGS__)

#define pr_perror(fmt, ...)	pr_p(pr_err, fmt, ##__VA_ARGS__)
#define pr_pwarn(fmt, ...)	pr_p(pr_warn, fmt, ##__VA_ARGS__)

#define CLOCK_TYPES							\
	ct(CLOCK_REALTIME),						\
	ct(CLOCK_REALTIME_COARSE),					\
	ct(CLOCK_MONOTONIC),						\
	ct(CLOCK_MONOTONIC_COARSE),					\
	ct(CLOCK_MONOTONIC_RAW),					\
	ct(CLOCK_BOOTTIME),						\
	ct(CLOCK_PROCESS_CPUTIME_ID),					\
	ct(CLOCK_THREAD_CPUTIME_ID),

#define ct(clock)	clock
static clockid_t clocks[] = {
	CLOCK_TYPES
};
#undef ct
#define ct(clock)	#clock
static char *clock_names[] = {
	CLOCK_TYPES
};

static int child_ns, parent_ns;

static int switch_ns(int fd)
{
	if (setns(fd, CLONE_NEWTIME)) {
		pr_perror("setns()");
		return -1;
	}

	return 0;
}

static int init_namespaces(void)
{
	char path[] = "/proc/self/ns/time";
	struct stat st1, st2;

	parent_ns = open(path, O_RDONLY);
	if (parent_ns <= 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	if (fstat(parent_ns, &st1)) {
		pr_perror("Unable to stat the parent timens");
		return -1;
	}

	if (unshare(CLONE_NEWTIME)) {
		pr_perror("Can't unshare() timens");
		return -1;
	}

	child_ns = open(path, O_RDONLY);
	if (child_ns <= 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	if (fstat(child_ns, &st2)) {
		pr_perror("Unable to stat the timens");
		return -1;
	}

	if (st1.st_ino == st2.st_ino) {
		pr_perror("The same child_ns after CLONE_NEWTIME");
		return -1;
	}

	return 0;
}

static inline int _gettime(clockid_t clk_id, struct timespec *res)
{
	if (clock_gettime(clk_id, res)) {
		pr_perror("clock_gettime(%d)", (int)clk_id);
		return -1;
	}
	return 0;
}

static int test_gettime(unsigned clock_index)
{
	struct timespec child_ts_old, child_ts_new;
	struct timespec parent_ts;

	if (switch_ns(child_ns)) {
		pr_err("switch_ns(%d)", child_ns);
		return -1;
	}

	if (_gettime(clocks[clock_index], &child_ts_old))
		return -1;

	child_ts_new.tv_nsec = child_ts_old.tv_nsec;
	child_ts_new.tv_sec = child_ts_old.tv_sec + TEN_DAYS_IN_SEC;

	if (clock_settime(clocks[clock_index], &child_ts_new)) {
		pr_perror("clock_settime(%s)", clock_names[clock_index]);
		return -1;
	}

	if (switch_ns(parent_ns)) {
		pr_err("switch_ns(%d)", parent_ns);
		return -1;
	}

	if (_gettime(clocks[clock_index], &parent_ts))
		return -1;

	if (parent_ts.tv_sec > child_ts_old.tv_sec + DAY_IN_SEC) {
		pr_fail("Parent's %s time has changed: %lu -> %lu",
			clock_names[clock_index],
			child_ts_old.tv_sec, parent_ts.tv_sec);
		/* Let's play nice and put it closer to original */
		clock_settime(clocks[clock_index], &parent_ts);
		return -1;
	}

	printk("Passed for %s", "OK", clock_names[clock_index]);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned i;

	if (init_namespaces())
		return 1;

	for (i = 0; i < ARRAY_SIZE(clocks); i++) {
		if (test_gettime(i))
			return 1;
	}

	return 0;
}
