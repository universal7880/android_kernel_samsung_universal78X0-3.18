/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BINDER_INTERNAL_H
#define _LINUX_BINDER_INTERNAL_H

#include <linux/init.h>
#include <linux/kref.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/uidgid.h>
#include <uapi/linux/android/binderfs.h>

struct binder_context {
	struct binder_node *binder_context_mgr_node;
	struct mutex context_mgr_node_lock;
	kuid_t binder_context_mgr_uid;
	const char *name;
};

struct binder_device {
	struct hlist_node hlist;
	struct miscdevice miscdev;
	struct binder_context context;
	struct kref ref;
	bool binderfs;
};

extern const struct file_operations binder_fops;
extern const struct file_operations binder_stats_fops;
extern char *binder_devices_param;

void binderfs_device_release(struct kref *ref);

#ifdef CONFIG_ANDROID_BINDERFS
int __init init_binderfs(void);
bool is_binderfs_device(const struct inode *inode);
#else
static inline int __init init_binderfs(void)
{
	return 0;
}

static inline bool is_binderfs_device(const struct inode *inode)
{
	return false;
}
#endif

#endif /* _LINUX_BINDER_INTERNAL_H */
