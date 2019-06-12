// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Andrei Vagin <avagin@openvz.org>
 * Author: Dmitry Safonov <dima@arista.com>
 */

#include <linux/export.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <asm/vdso.h>

ktime_t do_timens_ktime_to_host(clockid_t clockid, ktime_t tim, struct timens_offsets *ns_offsets)
{
	ktime_t koff;

	switch (clockid) {
	case CLOCK_MONOTONIC:
		koff = timespec64_to_ktime(ns_offsets->monotonic);
		break;
	case CLOCK_BOOTTIME:
	case CLOCK_BOOTTIME_ALARM:
		koff = timespec64_to_ktime(ns_offsets->boottime);
		break;
	default:
		return tim;
	}

	/* tim - off has to be in [0, KTIME_MAX) */
	if (tim < koff)
		tim = 0;
	else if (KTIME_MAX - tim < -koff)
		tim = KTIME_MAX;
	else
		tim = ktime_sub(tim, koff);

	return tim;
}

static struct ucounts *inc_time_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_TIME_NAMESPACES);
}

static void dec_time_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_TIME_NAMESPACES);
}

static struct time_namespace *create_time_ns(void)
{
	struct time_namespace *time_ns;

	time_ns = kmalloc(sizeof(struct time_namespace), GFP_KERNEL);
	if (time_ns) {
		kref_init(&time_ns->kref);
		time_ns->initialized = false;
	}
	return time_ns;
}

/*
 * Clone a new ns copying @old_ns, setting refcount to 1
 * @old_ns: namespace to clone
 * Return the new ns or ERR_PTR.
 */
static struct time_namespace *clone_time_ns(struct user_namespace *user_ns,
					  struct time_namespace *old_ns)
{
	struct time_namespace *ns;
	struct ucounts *ucounts;
	struct page *page;
	int err;

	err = -ENOSPC;
	ucounts = inc_time_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = create_time_ns();
	if (!ns)
		goto fail_dec;

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto fail_free;
	ns->offsets = page_address(page);
	BUILD_BUG_ON(sizeof(*ns->offsets) > PAGE_SIZE);

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto fail_page;

	ns->ucounts = ucounts;
	ns->ns.ops = &timens_operations;
	ns->user_ns = get_user_ns(user_ns);
	return ns;
fail_page:
	free_page((unsigned long)ns->offsets);
fail_free:
	kfree(ns);
fail_dec:
	dec_time_namespaces(ucounts);
fail:
	return ERR_PTR(err);
}

/*
 * Add a reference to old_ns, or clone it if @flags specify CLONE_NEWTIME.
 * In latter case, changes to the time of this process won't be seen by parent,
 * and vice versa.
 */
struct time_namespace *copy_time_ns(unsigned long flags,
	struct user_namespace *user_ns, struct time_namespace *old_ns)
{
	if (!(flags & CLONE_NEWTIME))
		return get_time_ns(old_ns);

	return clone_time_ns(user_ns, old_ns);
}

void free_time_ns(struct kref *kref)
{
	struct time_namespace *ns;

	ns = container_of(kref, struct time_namespace, kref);
	free_page((unsigned long)ns->offsets);
	dec_time_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	kfree(ns);
}

static struct time_namespace *to_time_ns(struct ns_common *ns)
{
	return container_of(ns, struct time_namespace, ns);
}

static struct ns_common *timens_get(struct task_struct *task)
{
	struct time_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->time_ns;
		get_time_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static struct ns_common *timens_for_children_get(struct task_struct *task)
{
	struct time_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->time_ns_for_children;
		get_time_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void timens_put(struct ns_common *ns)
{
	put_time_ns(to_time_ns(ns));
}

static int timens_install(struct nsproxy *nsproxy, struct ns_common *new)
{
	struct time_namespace *ns = to_time_ns(new);
	int ret;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	ret = vdso_join_timens(current);
	if (ret)
		return ret;

	get_time_ns(ns);
	get_time_ns(ns);
	put_time_ns(nsproxy->time_ns);
	put_time_ns(nsproxy->time_ns_for_children);
	nsproxy->time_ns = ns;
	nsproxy->time_ns_for_children = ns;
	ns->initialized = true;
	return 0;
}

int timens_on_fork(struct nsproxy *nsproxy, struct task_struct *tsk)
{
	struct ns_common *nsc = &nsproxy->time_ns_for_children->ns;
	struct time_namespace *ns = to_time_ns(nsc);
	int ret;

	if (nsproxy->time_ns == nsproxy->time_ns_for_children)
		return 0;

	ret = vdso_join_timens(tsk);
	if (ret)
		return ret;

	get_time_ns(ns);
	put_time_ns(nsproxy->time_ns);
	nsproxy->time_ns = ns;
	ns->initialized = true;

	return 0;
}

static struct user_namespace *timens_owner(struct ns_common *ns)
{
	return to_time_ns(ns)->user_ns;
}

static void show_offset(struct seq_file *m, int clockid, struct timespec64 *ts)
{
	seq_printf(m, "%d %lld %ld\n", clockid, ts->tv_sec, ts->tv_nsec);
}

void proc_timens_show_offsets(struct task_struct *p, struct seq_file *m)
{
	struct ns_common *ns;
	struct time_namespace *time_ns;
	struct timens_offsets *ns_offsets;

	ns = timens_for_children_get(p);
	if (!ns)
		return;
	time_ns = to_time_ns(ns);

	if (!time_ns->offsets) {
		put_time_ns(time_ns);
		return;
	}
	ns_offsets = time_ns->offsets;

	show_offset(m, CLOCK_MONOTONIC, &ns_offsets->monotonic);
	show_offset(m, CLOCK_BOOTTIME, &ns_offsets->boottime);
	put_time_ns(time_ns);
}

int proc_timens_set_offset(struct file *file, struct task_struct *p,
			   struct proc_timens_offset *offsets, int noffsets)
{
	struct ns_common *ns;
	struct time_namespace *time_ns;
	struct timens_offsets *ns_offsets;
	struct timespec64 *offset;
	struct timespec64 tp;
	int i, err;

	ns = timens_for_children_get(p);
	if (!ns)
		return -ESRCH;
	time_ns = to_time_ns(ns);

	if (!time_ns->offsets || time_ns->initialized ||
	    !file_ns_capable(file, time_ns->user_ns, CAP_SYS_TIME)) {
		put_time_ns(time_ns);
		return -EPERM;
	}
	ns_offsets = time_ns->offsets;

	for (i = 0; i < noffsets; i++) {
		struct proc_timens_offset *off = &offsets[i];

		switch (off->clockid) {
		case CLOCK_MONOTONIC:
			ktime_get_ts64(&tp);
			break;
		case CLOCK_BOOTTIME:
			ktime_get_boottime_ts64(&tp);
			break;
		default:
			err = -EINVAL;
			goto out;
		}

		err = -ERANGE;

		if (off->val.tv_sec > KTIME_SEC_MAX || off->val.tv_sec < -KTIME_SEC_MAX)
			goto out;

		tp = timespec64_add(tp, off->val);
		/*
		 * KTIME_SEC_MAX is divided by 2 to be sure that KTIME_MAX is
		 * still unreachable.
		 */
		if (tp.tv_sec < 0 || tp.tv_sec > KTIME_SEC_MAX / 2)
			goto out;
	}

	err = 0;
	/* don't report errors after this line */
	for (i = 0; i < noffsets; i++) {
		struct proc_timens_offset *off = &offsets[i];

		switch (off->clockid) {
		case CLOCK_MONOTONIC:
			offset = &ns_offsets->monotonic;
			break;
		case CLOCK_BOOTTIME:
			offset = &ns_offsets->boottime;
			break;
		default:
			goto out;
		}

		*offset = off->val;
	}

out:
	put_time_ns(time_ns);

	return err;
}

const struct proc_ns_operations timens_operations = {
	.name		= "time",
	.type		= CLONE_NEWTIME,
	.get		= timens_get,
	.put		= timens_put,
	.install	= timens_install,
	.owner		= timens_owner,
};

const struct proc_ns_operations timens_for_children_operations = {
	.name		= "time_for_children",
	.type		= CLONE_NEWTIME,
	.get		= timens_for_children_get,
	.put		= timens_put,
	.install	= timens_install,
	.owner		= timens_owner,
};

struct time_namespace init_time_ns = {
	.kref = KREF_INIT(3),
	.user_ns = &init_user_ns,
	.ns.inum = PROC_UTS_INIT_INO,
#ifdef CONFIG_UTS_NS
	.ns.ops = &timens_operations,
#endif
};

static int __init time_ns_init(void)
{
	return 0;
}
subsys_initcall(time_ns_init);
