// SPDX-License-Identifier: GPL-2.0
/*
 * Binder filesystem, based on the Android common binderfs implementation.
 * This port supports global statistics and Binder devices in the initial
 * user namespace.
 */

#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/idr.h>
#include <linux/kdev_t.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "binder_internal.h"

#define BINDERFS_MAX_MINORS	(1U << MINORBITS)
#define BINDERFS_ROOT_INO	1
#define BINDERFS_CONTROL_INO	2
#define BINDERFS_DEVICE_INO	3

struct binderfs_info {
	struct dentry *control;
	unsigned int max_devices;
	unsigned int device_count;
	bool global_stats;
};

static dev_t binderfs_dev;
static DEFINE_IDA(binderfs_minors);
static DEFINE_MUTEX(binderfs_minors_lock);

bool is_binderfs_device(const struct inode *inode)
{
	return inode->i_sb->s_magic == BINDERFS_SUPER_MAGIC;
}

static void binderfs_evict_inode(struct inode *inode)
{
	struct binderfs_info *info = inode->i_sb->s_fs_info;
	struct binder_device *device = inode->i_private;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (!S_ISCHR(inode->i_mode))
		return;

	mutex_lock(&binderfs_minors_lock);
	ida_simple_remove(&binderfs_minors, MINOR(inode->i_rdev));
	if (device)
		info->device_count--;
	mutex_unlock(&binderfs_minors_lock);

	if (device)
		kref_put(&device->ref, binderfs_device_release);
}

static int binderfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct binderfs_info *info = root->d_sb->s_fs_info;

	if (info->max_devices != BINDERFS_MAX_MINORS)
		seq_printf(m, ",max=%u", info->max_devices);
	if (info->global_stats)
		seq_puts(m, ",stats=global");
	return 0;
}

static const struct super_operations binderfs_super_ops = {
	.evict_inode = binderfs_evict_inode,
	.show_options = binderfs_show_options,
	.statfs = simple_statfs,
};

static int binderfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct binderfs_info *info = dir->i_sb->s_fs_info;

	if (dentry == info->control)
		return -EPERM;
	return simple_unlink(dir, dentry);
}

static int binderfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct binderfs_info *info = old_dir->i_sb->s_fs_info;

	if (old_dentry == info->control || new_dentry == info->control)
		return -EPERM;
	return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static const struct inode_operations binderfs_dir_ops = {
	.lookup = simple_lookup,
	.unlink = binderfs_unlink,
	.rename = binderfs_rename,
};

static struct inode *binderfs_new_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode = new_inode(sb);

	if (!inode)
		return NULL;

	inode->i_mode = mode;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	if (S_ISDIR(mode)) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		set_nlink(inode, 2);
	}
	return inode;
}

static int binderfs_add_device(struct super_block *sb,
			       struct binderfs_device *req,
			       struct binderfs_device __user *user_req)
{
	struct binderfs_info *info = sb->s_fs_info;
	struct inode *dir = d_inode(sb->s_root);
	struct binder_device *device;
	struct dentry *dentry;
	struct inode *inode;
	int minor, ret;

	req->name[BINDERFS_MAX_NAME] = '\0';
	if (!req->name[0] || strchr(req->name, '/') ||
	    !strcmp(req->name, ".") || !strcmp(req->name, ".."))
		return -EINVAL;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;

	ret = -ENOMEM;
	device->context.name = kstrdup(req->name, GFP_KERNEL);
	if (!device->context.name)
		goto free_device;
	device->binderfs = true;
	device->context.binder_context_mgr_uid = INVALID_UID;
	mutex_init(&device->context.context_mgr_node_lock);
	kref_init(&device->ref);

	/* Until a minor is assigned, eviction must treat it as a regular inode. */
	inode = binderfs_new_inode(sb, S_IFREG);
	if (!inode)
		goto free_name;

	mutex_lock(&binderfs_minors_lock);
	minor = -ENOSPC;
	if (info->device_count < info->max_devices)
		minor = ida_simple_get(&binderfs_minors, 0,
				       BINDERFS_MAX_MINORS, GFP_KERNEL);
	if (minor >= 0)
		info->device_count++;
	mutex_unlock(&binderfs_minors_lock);
	if (minor < 0) {
		ret = minor;
		iput(inode);
		goto free_name;
	}

	inode->i_ino = BINDERFS_DEVICE_INO + minor;
	init_special_inode(inode, S_IFCHR | 0600, MKDEV(MAJOR(binderfs_dev), minor));
	inode->i_fop = &binder_fops;
	inode->i_private = device;

	req->major = MAJOR(binderfs_dev);
	req->minor = minor;

	/* Copy to userspace before taking the directory lock, as upstream does. */
	if (user_req && copy_to_user(user_req, req, sizeof(*req))) {
		iput(inode);
		return -EFAULT;
	}

	inode_lock(dir);
	dentry = lookup_one_len(req->name, sb->s_root, strlen(req->name));
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
	} else if (d_inode(dentry)) {
		dput(dentry);
		ret = -EEXIST;
	} else {
		d_instantiate(dentry, inode);
		fsnotify_create(dir, dentry);
		ret = 0;
	}
	inode_unlock(dir);
	if (ret)
		iput(inode);
	return ret;

free_name:
	kfree(device->context.name);
free_device:
	kfree(device);
	return ret;
}

static long binderfs_control_ioctl(struct file *file, unsigned int cmd,
				    unsigned long arg)
{
	struct binderfs_device __user *user_req = (void __user *)arg;
	struct binderfs_device req;

	if (cmd != BINDER_CTL_ADD)
		return -ENOTTY;
	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;
	return binderfs_add_device(file_inode(file)->i_sb, &req, user_req);
}

#ifdef CONFIG_COMPAT
static long binderfs_control_compat_ioctl(struct file *file, unsigned int cmd,
					   unsigned long arg)
{
	return binderfs_control_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations binderfs_control_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.unlocked_ioctl = binderfs_control_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = binderfs_control_compat_ioctl,
#endif
	.llseek = no_llseek,
};

static int binderfs_create_control(struct super_block *sb)
{
	struct binderfs_info *info = sb->s_fs_info;
	struct inode *inode;
	struct dentry *dentry;
	int minor;

	inode = binderfs_new_inode(sb, S_IFREG);
	if (!inode)
		return -ENOMEM;

	mutex_lock(&binderfs_minors_lock);
	minor = ida_simple_get(&binderfs_minors, 0, BINDERFS_MAX_MINORS, GFP_KERNEL);
	mutex_unlock(&binderfs_minors_lock);
	if (minor < 0) {
		iput(inode);
		return minor;
	}

	inode->i_ino = BINDERFS_CONTROL_INO;
	init_special_inode(inode, S_IFCHR | 0600, MKDEV(MAJOR(binderfs_dev), minor));
	inode->i_fop = &binderfs_control_fops;

	dentry = d_alloc_name(sb->s_root, "binder-control");
	if (!dentry) {
		iput(inode);
		return -ENOMEM;
	}

	info->control = dentry;
	d_add(dentry, inode);
	return 0;
}

static int binderfs_create_stats(struct super_block *sb)
{
	struct dentry *dir, *file;
	struct inode *inode;

	inode = binderfs_new_inode(sb, S_IFDIR | 0755);
	if (!inode)
		return -ENOMEM;
	inode->i_ino = iunique(sb, BINDERFS_MAX_MINORS + BINDERFS_DEVICE_INO);
	dir = d_alloc_name(sb->s_root, "binder_logs");
	if (!dir) {
		iput(inode);
		return -ENOMEM;
	}
	d_add(dir, inode);
	inc_nlink(d_inode(sb->s_root));

	inode = binderfs_new_inode(sb, S_IFREG | 0444);
	if (!inode)
		return -ENOMEM;
	inode->i_ino = iunique(sb, BINDERFS_MAX_MINORS + BINDERFS_DEVICE_INO);
	inode->i_fop = &binder_stats_fops;
	file = d_alloc_name(dir, "stats");
	if (!file) {
		iput(inode);
		return -ENOMEM;
	}
	d_add(file, inode);
	return 0;
}

static int binderfs_parse_options(struct binderfs_info *info, char *options)
{
	char *option;

	info->max_devices = BINDERFS_MAX_MINORS;

	while ((option = strsep(&options, ",")) != NULL) {
		if (!*option)
			continue;
		if (!strcmp(option, "stats=global")) {
			if (!capable(CAP_SYS_ADMIN))
				return -EPERM;
			info->global_stats = true;
		} else if (!strncmp(option, "max=", 4)) {
			if (kstrtouint(option + 4, 10, &info->max_devices) ||
			    info->max_devices > BINDERFS_MAX_MINORS)
				return -EINVAL;
		} else {
			return -EINVAL;
		}
	}
	return 0;
}

static int binderfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct binderfs_device req = { };
	struct binderfs_info *info;
	struct inode *root;
	const char *name = binder_devices_param;
	size_t len;
	int ret;

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = BINDERFS_SUPER_MAGIC;
	sb->s_op = &binderfs_super_ops;
	sb->s_time_gran = 1;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	sb->s_fs_info = info;

	ret = binderfs_parse_options(info, data);
	if (ret)
		return ret;

	root = binderfs_new_inode(sb, S_IFDIR | 0755);
	if (!root)
		return -ENOMEM;
	root->i_ino = BINDERFS_ROOT_INO;
	root->i_op = &binderfs_dir_ops;

	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;

	ret = binderfs_create_control(sb);
	if (ret)
		return ret;

	while ((len = strcspn(name, ",")) != 0) {
		if (len > BINDERFS_MAX_NAME)
			return -E2BIG;
		memcpy(req.name, name, len);
		req.name[len] = '\0';
		ret = binderfs_add_device(sb, &req, NULL);
		if (ret)
			return ret;
		name += len;
		if (*name == ',')
			name++;
	}

	if (info->global_stats)
		return binderfs_create_stats(sb);
	return 0;
}

static struct dentry *binderfs_mount(struct file_system_type *type, int flags,
				     const char *dev_name, void *data)
{
	return mount_nodev(type, flags | MS_NOEXEC, data, binderfs_fill_super);
}

static void binderfs_kill_super(struct super_block *sb)
{
	struct binderfs_info *info = sb->s_fs_info;

	kill_litter_super(sb);
	kfree(info);
}

static struct file_system_type binder_fs_type = {
	.owner = THIS_MODULE,
	.name = "binder",
	.mount = binderfs_mount,
	.kill_sb = binderfs_kill_super,
};

int __init init_binderfs(void)
{
	int ret;

	ret = alloc_chrdev_region(&binderfs_dev, 0, BINDERFS_MAX_MINORS, "binder");
	if (ret)
		return ret;

	ret = register_filesystem(&binder_fs_type);
	if (ret)
		unregister_chrdev_region(binderfs_dev, BINDERFS_MAX_MINORS);
	return ret;
}
