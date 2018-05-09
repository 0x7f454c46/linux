/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/param.h>
#include <linux/sched.h>

#define DEFAULT_RATELIMIT_INTERVAL	(5 * HZ)
#define DEFAULT_RATELIMIT_BURST		10

/* issue num suppressed message on exit */
#define RATELIMIT_MSG_ON_RELEASE	BIT(0)

struct ratelimit_state {
	atomic_t	printed;
	atomic_t	missed;

	int		interval;
	int		burst;
	unsigned long	begin;
	unsigned long	flags;
};

#define RATELIMIT_STATE_INIT(interval_init, burst_init) {		\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
		.printed	= ATOMIC_INIT(0),			\
		.missed		= ATOMIC_INIT(0),			\
	}

#define RATELIMIT_STATE_INIT_DISABLED					\
	RATELIMIT_STATE_INIT(0, DEFAULT_RATELIMIT_BURST)

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(interval_init, burst_init)

static inline void ratelimit_state_init(struct ratelimit_state *rs,
					int interval, int burst)
{
	memset(rs, 0, sizeof(*rs));

	rs->interval	= interval;
	rs->burst	= burst;
	atomic_set(&rs->printed, 0);
	atomic_set(&rs->missed, 0);
}

static inline void ratelimit_default_init(struct ratelimit_state *rs)
{
	return ratelimit_state_init(rs, DEFAULT_RATELIMIT_INTERVAL,
					DEFAULT_RATELIMIT_BURST);
}

/*
 * Keeping It Simple: not reenterable and not safe for concurrent
 * ___ratelimit() call as used only by devkmsg_release().
 */
static inline void ratelimit_state_exit(struct ratelimit_state *rs)
{
	int missed;

	if (!(rs->flags & RATELIMIT_MSG_ON_RELEASE))
		return;

	missed = atomic_xchg(&rs->missed, 0);
	if (missed)
		pr_warn("%s: %d output lines suppressed due to ratelimiting\n",
			current->comm, missed);
}

static inline void
ratelimit_set_flags(struct ratelimit_state *rs, unsigned long flags)
{
	rs->flags = flags;
}

extern struct ratelimit_state printk_ratelimit_state;

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);
#define __ratelimit(state) ___ratelimit(state, __func__)

#ifdef CONFIG_PRINTK

#define WARN_ON_RATELIMIT(condition, state)	({		\
	bool __rtn_cond = !!(condition);			\
	WARN_ON(__rtn_cond && __ratelimit(state));		\
	__rtn_cond;						\
})

#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);	\
	int rtn = !!(condition);				\
								\
	if (unlikely(rtn && __ratelimit(&_rs)))			\
		WARN(rtn, format, ##__VA_ARGS__);		\
								\
	rtn;							\
})

#else

#define WARN_ON_RATELIMIT(condition, state)			\
	WARN_ON(condition)

#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	int rtn = WARN(condition, format, ##__VA_ARGS__);	\
	rtn;							\
})

#endif

#endif /* _LINUX_RATELIMIT_H */
