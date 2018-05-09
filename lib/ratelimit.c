/*
 * ratelimit.c - Do something with rate limit.
 *
 * Isolated from kernel/printk.c by Dave Young <hidave.darkstar@gmail.com>
 *
 * 2008-05-01 rewrite the function and use a ratelimit_state data struct as
 * parameter. Now every user can use their own standalone ratelimit_state.
 *
 * This file is released under the GPLv2.
 */

#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <linux/export.h>

static void ratelimit_end_interval(struct ratelimit_state *rs, const char *func)
{
	rs->begin = jiffies;

	if (!(rs->flags & RATELIMIT_MSG_ON_RELEASE)) {
		unsigned int missed = atomic_xchg(&rs->missed, 0);

		if (missed)
			pr_warn("%s: %u callbacks suppressed\n", func, missed);
	}
}

/*
 * __ratelimit - rate limiting
 * @rs: ratelimit_state data
 * @func: name of calling function
 *
 * This enforces a rate limit: not more than @rs->burst callbacks
 * in every @rs->interval
 *
 * RETURNS:
 * 0 means callbacks will be suppressed.
 * 1 means go ahead and do it.
 */
int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
	if (!rs->interval)
		return 1;

	if (unlikely(!rs->burst)) {
		atomic_add_unless(&rs->missed, 1, -1);
		if (time_is_before_jiffies(rs->begin + rs->interval))
			ratelimit_end_interval(rs, func);

		return 0;
	}

	if (atomic_add_unless(&rs->printed, 1, rs->burst))
		return 1;

	if (time_is_before_jiffies(rs->begin + rs->interval)) {
		if (atomic_cmpxchg(&rs->printed, rs->burst, 0))
			ratelimit_end_interval(rs, func);
	}

	if (atomic_add_unless(&rs->printed, 1, rs->burst))
		return 1;

	atomic_add_unless(&rs->missed, 1, -1);

	return 0;
}
EXPORT_SYMBOL(___ratelimit);
